import * as cp from 'child_process';
import * as http from 'http';
import * as url from 'url';
import * as net from 'net';
import * as path from 'path';
import * as crypto from 'crypto';
// import * as express from 'express';
import { RunOnceScheduler } from 'vs/base/common/async';
import { VSBuffer } from 'vs/base/common/buffer';
import { Emitter, Event } from 'vs/base/common/event';
import { IDisposable } from 'vs/base/common/lifecycle';
import { ClientConnectionEvent, IPCServer } from 'vs/base/parts/ipc/common/ipc';
import { PersistentProtocol, ProtocolConstants } from 'vs/base/parts/ipc/common/ipc.net';
import { NodeSocket, WebSocketNodeSocket } from 'vs/base/parts/ipc/node/ipc.net';
import { ServicesAccessor } from 'vs/platform/instantiation/common/instantiation';
import { InstantiationService } from 'vs/platform/instantiation/common/instantiationService';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection';
import { ILogService } from 'vs/platform/log/common/log';
import { ConnectionType, ErrorMessage, HandshakeMessage, IRemoteExtensionHostStartParams, OKMessage, SignRequest } from 'vs/platform/remote/common/remoteAgentConnection';
import { RemoteAgentConnectionContext } from 'vs/platform/remote/common/remoteAgentEnvironment';
import { IExtHostReadyMessage, IExtHostSocketMessage } from 'vs/workbench/services/extensions/common/extensionHostProtocol';
import { ErrorListenerCallback, ErrorListenerUnbind, isPromiseCanceledError } from 'vs/base/common/errors';
import { collectRequestData, serveError, serveFile } from 'vs/server/node/http';
import { authenticated, ensureAuthenticated, getPasswordMethod, handlePasswordValidation } from 'vs/server/node/auth';
import { URI } from 'vs/base/common/uri';
import { FileAccess } from 'vs/base/common/network';
import { IRemoteConsoleLog } from 'vs/base/common/console';
import { args, devMode } from 'vs/server/node/args';
import product from 'vs/platform/product/common/product';
import { IRawURITransformerFactory } from 'vs/server/node/server.main';
import { NativeEnvironmentService } from 'vs/platform/environment/node/environmentService';

export const APP_ROOT = path.join(__dirname, '..', '..', '..', '..');
export const uriTransformerPath = path.join(APP_ROOT, 'out/serverUriTransformer');
export const rawURITransformerFactory: IRawURITransformerFactory = <any>require.__$__nodeRequire(uriTransformerPath);

export const LOGIN = path.join(APP_ROOT, 'out', 'vs', 'server', 'browser', 'workbench', 'login.html');
export const WEB_MAIN = path.join(APP_ROOT, 'out', 'vs', 'server', 'browser', 'workbench', 'workbench.html');
export const WEB_MAIN_DEV = path.join(APP_ROOT, 'out', 'vs', 'server', 'browser', 'workbench', 'workbench-dev.html');

export interface IStartServerResult {
	installingInitialExtensions?: Promise<void>
}

export interface IServerOptions {
	port?: number;
	main?: string
	mainDev?: string
	skipExtensions?: Set<string>
	configure?(services: ServiceCollection, channelServer: IPCServer<RemoteAgentConnectionContext>): void
	start?(accessor: ServicesAccessor, channelServer: IPCServer<RemoteAgentConnectionContext>): IStartServerResult | void

	configureExtensionHostForkOptions?(opts: cp.ForkOptions, accessor: ServicesAccessor, channelServer: IPCServer<RemoteAgentConnectionContext>): void;
	configureExtensionHostProcess?(extensionHost: cp.ChildProcess, accessor: ServicesAccessor, channelServer: IPCServer<RemoteAgentConnectionContext>): IDisposable;

	handleRequest?(pathname: string | null, req: http.IncomingMessage, res: http.ServerResponse, accessor: ServicesAccessor, channelServer: IPCServer<RemoteAgentConnectionContext>): Promise<boolean>;
}

export interface ManagementProtocol {
	protocol: PersistentProtocol
	graceTimeReconnection: RunOnceScheduler
	shortGraceTimeReconnection: RunOnceScheduler
}

export interface Client {
	management?: ManagementProtocol
	extensionHost?: cp.ChildProcess
}

// Avoid circular dependency on EventEmitter by implementing a subset of the interface.
export class ErrorHandler {
	private unexpectedErrorHandler: (e: any) => void;
	private listeners: ErrorListenerCallback[];

	constructor() {

		this.listeners = [];

		this.unexpectedErrorHandler = function (e: any) {
			setTimeout(() => {
				if (e.stack) {
					throw new Error(e.message + '\n\n' + e.stack);
				}

				throw e;
			}, 0);
		};
	}

	addListener(listener: ErrorListenerCallback): ErrorListenerUnbind {
		this.listeners.push(listener);

		return () => {
			this._removeListener(listener);
		};
	}

	private emit(e: any): void {
		this.listeners.forEach((listener) => {
			listener(e);
		});
	}

	private _removeListener(listener: ErrorListenerCallback): void {
		this.listeners.splice(this.listeners.indexOf(listener), 1);
	}

	setUnexpectedErrorHandler(newUnexpectedErrorHandler: (e: any) => void): void {
		this.unexpectedErrorHandler = newUnexpectedErrorHandler;
	}

	getUnexpectedErrorHandler(): (e: any) => void {
		return this.unexpectedErrorHandler;
	}

	onUnexpectedError(e: any): void {
		this.unexpectedErrorHandler(e);
		this.emit(e);
	}

	// For external errors, we don't want the listeners to be called
	onUnexpectedExternalError(e: any): void {
		this.unexpectedErrorHandler(e);
	}
}

export const errorHandler = new ErrorHandler();

export function setUnexpectedErrorHandler(newUnexpectedErrorHandler: (e: any) => void): void {
	errorHandler.setUnexpectedErrorHandler(newUnexpectedErrorHandler);
}

export function onUnexpectedError(e: any): undefined {
	// ignore errors from cancelled promises
	if (!isPromiseCanceledError(e)) {
		errorHandler.onUnexpectedError(e);
	}
	return undefined;
}

export function onUnexpectedExternalError(e: any): undefined {
	// ignore errors from cancelled promises
	if (!isPromiseCanceledError(e)) {
		errorHandler.onUnexpectedExternalError(e);
	}
	return undefined;
}

function safeDisposeProtocolAndSocket(protocol: PersistentProtocol): void {
	try {
		protocol.acceptDisconnect();
		const socket = protocol.getSocket();
		protocol.dispose();
		socket.dispose();
	} catch (err) {
		onUnexpectedError(err);
	}
}

export function handleHttp(options: IServerOptions, instantiationService: InstantiationService, logService: ILogService, environmentService: NativeEnvironmentService, onDidClientConnectEmitter: Emitter<ClientConnectionEvent>, channelServer: IPCServer<RemoteAgentConnectionContext>) {

	const clients = new Map<string, Client>();

	// const app = express();

	const server = http.createServer(async (req, res) => {
		if (!req.url) {
			return serveError(req, res, 400, 'Bad Request.');
		}
		try {
			const parsedUrl = url.parse(req.url, true);
			const pathname = parsedUrl.pathname;

			if (options.handleRequest && await instantiationService.invokeFunction(accessor => options.handleRequest!(pathname, req, res, accessor, channelServer))) {
				return;
			}

			if (pathname === '/') {
				return serveFile(logService, req, res, await authenticated(args, req) ? devMode ? options.mainDev || WEB_MAIN_DEV : options.main || WEB_MAIN : LOGIN);
			}
			if (pathname === '/login') {
				const password = (await collectRequestData(req)).password;
				const passwordMethod = getPasswordMethod(args.hashedPassword);
				const { isPasswordValid, hashedPassword } = await handlePasswordValidation({
					passwordMethod,
					hashedPasswordFromArgs: args.hashedPassword,
					passwordFromRequestBody: password,
					passwordFromArgs: args.password,
				});

				if (isPasswordValid) {
					// The hash does not add any actual security but we do it for
					// obfuscation purposes (and as a side effect it handles escaping).
					res.writeHead(302, {
						'Location': '/',
						'Set-Cookie': `key=${hashedPassword}`,
						'Content-Type': 'text/plain'
					});
					return res.end('');
				} else {
					res.writeHead(302, {
						'Location': '/',
						'Content-Type': 'text/plain'
					});
					return res.end('');
				}
			}
			if (!await ensureAuthenticated(args, req, res)) {
				return;
			}
			if (pathname === '/manifest.json') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				return res.end(JSON.stringify({
					'name': product.nameLong,
					'short_name': product.nameShort,
					'start_url': '/',
					'lang': 'en-US',
					'display': 'standalone'
				}));
			}
			if (pathname === '/vscode-remote-resource') {
				const filePath = parsedUrl.query['path'];
				const fsPath = typeof filePath === 'string' && URI.from({ scheme: 'file', path: filePath }).fsPath;
				if (!fsPath) {
					return serveError(req, res, 400, 'Bad Request.');
				}
				return serveFile(logService, req, res, fsPath);
			}
			if (pathname) {
				let relativeFilePath;
				if (/^\/static\//.test(pathname)) {
					relativeFilePath = path.normalize(decodeURIComponent(pathname.substr('/static/'.length)));
				} else {
					relativeFilePath = path.normalize(decodeURIComponent(pathname));
				}
				return serveFile(logService, req, res, path.join(APP_ROOT, relativeFilePath));
			}



			// TODO uri callbacks ?
			logService.error(`${req.method} ${req.url} not found`);
			return serveError(req, res, 404, 'Not found.');
		} catch (error) {
			logService.error(error);

			return serveError(req, res, 500, 'Internal Server Error.');
		}
	});
	server.on('error', e => logService.error(e));
	server.on('upgrade', (req: http.IncomingMessage, socket: net.Socket) => {
		if (req.headers['upgrade'] !== 'websocket' || !req.url) {
			logService.error(`failed to upgrade for header "${req.headers['upgrade']}" and url: "${req.url}".`);
			socket.end('HTTP/1.1 400 Bad Request');
			return;
		}
		const { query } = url.parse(req.url, true);
		// /?reconnectionToken=c0e3a8af-6838-44fb-851b-675401030831&reconnection=false&skipWebSocketFrames=false
		const reconnection = 'reconnection' in query && query['reconnection'] === 'true';
		let token: string | undefined;
		if ('reconnectionToken' in query && typeof query['reconnectionToken'] === 'string') {
			token = query['reconnectionToken'];
		}
		// TODO skipWebSocketFrames (support of VS Code desktop?)
		if (!token) {
			logService.error(`missing token for "${req.url}".`);
			socket.end('HTTP/1.1 400 Bad Request');
			return;
		}
		logService.info(`[${token}] Socket upgraded for "${req.url}".`);
		socket.on('error', e => {
			logService.error(`[${token}] Socket failed for "${req.url}".`, e);
		});

		const acceptKey = req.headers['sec-websocket-key'];
		const hash = crypto.createHash('sha1').update(acceptKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
		const responseHeaders = ['HTTP/1.1 101 Web Socket Protocol Handshake', 'Upgrade: WebSocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${hash}`];

		let permessageDeflate = false;
		if (String(req.headers['sec-websocket-extensions']).indexOf('permessage-deflate') !== -1) {
			permessageDeflate = true;
			responseHeaders.push('Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=15');
		}

		socket.write(responseHeaders.join('\r\n') + '\r\n\r\n');

		const client = clients.get(token) || {};
		clients.set(token, client);

		const webSocket = new WebSocketNodeSocket(new NodeSocket(socket), permessageDeflate, null, permessageDeflate);
		const protocol = new PersistentProtocol(webSocket);
		const controlListener = protocol.onControlMessage(async raw => {
			const msg = <HandshakeMessage>JSON.parse(raw.toString());
			if (msg.type === 'error') {
				logService.error(`[${token}] error control message:`, msg.reason);
				safeDisposeProtocolAndSocket(protocol);
			} else if (msg.type === 'auth') {
				protocol.sendControl(VSBuffer.fromString(JSON.stringify({
					type: 'sign',
					data: product.nameShort + ' Server'
				} as SignRequest)));
			} else if (msg.type === 'connectionType') {
				controlListener.dispose();
				// TODO version matching msg.commit
				// TODO auth check msg.signedData
				for (const [token, client] of clients) {
					if (client.management) {
						if (client.management.graceTimeReconnection.isScheduled() && !client.management.shortGraceTimeReconnection.isScheduled()) {
							logService.info(`[${token}] Another connection is established, closing this connection after ${ProtocolConstants.ReconnectionShortGraceTime}ms reconnection timeout.`);
							client.management.shortGraceTimeReconnection.schedule();
						}
					}
					if (client.extensionHost) {
						client.extensionHost.send({
							type: 'VSCODE_EXTHOST_IPC_REDUCE_GRACE_TIME'
						});
					}
				}
				if (msg.desiredConnectionType === ConnectionType.Management) {
					if (!reconnection) {
						if (client.management) {
							logService.error(`[${token}] Falied to connect: management connection is already running.`);
							protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'error', reason: 'Management connection is already running.' } as ErrorMessage)));
							safeDisposeProtocolAndSocket(protocol);
							return;
						}

						const onDidClientDisconnectEmitter = new Emitter<void>();
						let disposed = false;
						function dispose(): void {
							if (disposed) {
								return;
							}
							disposed = true;
							graceTimeReconnection.dispose();
							shortGraceTimeReconnection.dispose();
							client.management = undefined;
							protocol.sendDisconnect();
							const socket = protocol.getSocket();
							protocol.dispose();
							socket.end();
							onDidClientDisconnectEmitter.fire(undefined);
							onDidClientDisconnectEmitter.dispose();
							logService.info(`[${token}] Management connection is disposed.`);
						}

						protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'ok' } as OKMessage)));
						const graceTimeReconnection = new RunOnceScheduler(() => {
							logService.info(`[${token}] Management connection expired after ${ProtocolConstants.ReconnectionGraceTime}ms (grace).`);
							dispose();
						}, ProtocolConstants.ReconnectionGraceTime);
						const shortGraceTimeReconnection = new RunOnceScheduler(() => {
							logService.info(`[${token}] Management connection expired after ${ProtocolConstants.ReconnectionShortGraceTime}ms (short grace).`);
							dispose();
						}, ProtocolConstants.ReconnectionShortGraceTime);
						client.management = { protocol, graceTimeReconnection, shortGraceTimeReconnection };
						protocol.onDidDispose(() => dispose());
						protocol.onSocketClose(() => {
							logService.info(`[${token}] Management connection socket is closed, waiting to reconnect within ${ProtocolConstants.ReconnectionGraceTime}ms.`);
							graceTimeReconnection.schedule();
						});
						onDidClientConnectEmitter.fire({ protocol, onDidClientDisconnect: onDidClientDisconnectEmitter.event });
						logService.info(`[${token}] Management connection is connected.`);
					} else {
						if (!client.management) {
							logService.error(`[${token}] Failed to reconnect: management connection is not running.`);
							protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'error', reason: 'Management connection is not running.' } as ErrorMessage)));
							safeDisposeProtocolAndSocket(protocol);
							return;
						}

						protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'ok' } as OKMessage)));
						client.management.graceTimeReconnection.cancel();
						client.management.shortGraceTimeReconnection.cancel();
						client.management.protocol.beginAcceptReconnection(protocol.getSocket(), protocol.readEntireBuffer());
						client.management.protocol.endAcceptReconnection();
						protocol.dispose();
						logService.info(`[${token}] Management connection is reconnected.`);
					}
				} else if (msg.desiredConnectionType === ConnectionType.ExtensionHost) {
					const params: IRemoteExtensionHostStartParams = {
						language: 'en',
						...msg.args
						// TODO what if params.port is 0?
					};

					if (!reconnection) {
						if (client.extensionHost) {
							logService.error(`[${token}] Falied to connect: extension host is already running.`);
							protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'error', reason: 'Extension host is already running.' } as ErrorMessage)));
							safeDisposeProtocolAndSocket(protocol);
							return;
						}

						protocol.sendControl(VSBuffer.fromString(JSON.stringify({ debugPort: params.port } /* Omit<IExtensionHostConnectionResult, 'protocol'> */)));
						const initialDataChunk = Buffer.from(protocol.readEntireBuffer().buffer).toString('base64');
						protocol.dispose();
						socket.pause();
						await webSocket.drain();

						try {
							// see src/vs/workbench/services/extensions/electron-browser/localProcessExtensionHost.ts
							const opts: cp.ForkOptions = {
								env: {
									...process.env,
									VSCODE_AMD_ENTRYPOINT: 'vs/workbench/services/extensions/node/extensionHostProcess',
									VSCODE_PIPE_LOGGING: 'true',
									VSCODE_VERBOSE_LOGGING: 'true',
									VSCODE_LOG_NATIVE: 'false',
									VSCODE_EXTHOST_WILL_SEND_SOCKET: 'true',
									VSCODE_HANDLES_UNCAUGHT_ERRORS: 'true',
									VSCODE_LOG_STACK: 'true',
									VSCODE_LOG_LEVEL: environmentService.verbose ? 'trace' : environmentService.logLevel
								},
								// see https://github.com/akosyakov/gitpod-code/blob/33b49a273f1f6d44f303426b52eaf89f0f5cc596/src/vs/base/parts/ipc/node/ipc.cp.ts#L72-L78
								execArgv: [],
								silent: true
							};
							if (typeof params.port === 'number') {
								if (params.port !== 0) {
									opts.execArgv = [
										'--nolazy',
										(params.break ? '--inspect-brk=' : '--inspect=') + params.port
									];
								} else {
									// TODO we should return a dynamically allocated port to the client,
									// it is better to avoid it?
									opts.execArgv = ['--inspect-port=0'];
								}
							}
							if (options.configureExtensionHostForkOptions) {
								instantiationService.invokeFunction(accessor => options.configureExtensionHostForkOptions!(opts, accessor, channelServer));
							}
							const extensionHost = cp.fork(FileAccess.asFileUri('bootstrap-fork', require).fsPath, ['--type=extensionHost', '--uriTransformerPath=' + uriTransformerPath], opts);
							extensionHost.stdout!.setEncoding('utf8');
							extensionHost.stderr!.setEncoding('utf8');
							Event.fromNodeEventEmitter<string>(extensionHost.stdout!, 'data')(msg => logService.info(`[${token}][extension host][${extensionHost.pid}][stdout] ${msg}`));
							Event.fromNodeEventEmitter<string>(extensionHost.stderr!, 'data')(msg => logService.info(`[${token}][extension host][${extensionHost.pid}][stderr] ${msg}`));
							extensionHost.on('message', msg => {
								if (msg && (<IRemoteConsoleLog>msg).type === '__$console') {
									logService.info(`[${token}][extension host][${extensionHost.pid}][__$console] ${(<IRemoteConsoleLog>msg).arguments}`);
								}
							});

							let disposed = false;
							let toDispose: IDisposable = { dispose: () => { } };
							function dispose(): void {
								if (disposed) {
									return;
								}
								disposed = true;
								toDispose.dispose();
								socket.end();
								extensionHost.kill();
								client.extensionHost = undefined;
								logService.info(`[${token}] Extension host is disconnected.`);
							}

							extensionHost.on('error', err => {
								dispose();
								logService.error(`[${token}] Extension host failed with: `, err);
							});
							extensionHost.on('exit', (code: number, signal: string) => {
								dispose();
								if (code !== 0 && signal !== 'SIGTERM') {
									logService.error(`[${token}] Extension host exited with code: ${code} and signal: ${signal}.`);
								}
							});

							const readyListener = (msg: any) => {
								if (msg && (<IExtHostReadyMessage>msg).type === 'VSCODE_EXTHOST_IPC_READY') {
									extensionHost.removeListener('message', readyListener);
									const inflateBytes = Buffer.from(webSocket.recordedInflateBytes.buffer).toString('base64');
									extensionHost.send({
										type: 'VSCODE_EXTHOST_IPC_SOCKET',
										initialDataChunk,
										skipWebSocketFrames: false, // TODO skipWebSocketFrames - i.e. when we connect from Node (VS Code?)
										permessageDeflate,
										inflateBytes
									} as IExtHostSocketMessage, socket);
									logService.info(`[${token}] Extension host is connected.`);
								}
							};
							extensionHost.on('message', readyListener);

							if (options.configureExtensionHostProcess) {
								toDispose = instantiationService.invokeFunction(accessor => options.configureExtensionHostProcess!(extensionHost, accessor, channelServer));
							}
							client.extensionHost = extensionHost;
							logService.info(`[${token}] Extension host is started.`);
						} catch (e) {
							logService.error(`[${token}] Failed to start the extension host process: `, e);
						}
					} else {
						if (!client.extensionHost) {
							logService.error(`[${token}] Failed to reconnect: extension host is not running.`);
							protocol.sendControl(VSBuffer.fromString(JSON.stringify({ type: 'error', reason: 'Extension host is not running.' } as ErrorMessage)));
							safeDisposeProtocolAndSocket(protocol);
							return;
						}

						protocol.sendControl(VSBuffer.fromString(JSON.stringify({ debugPort: params.port } /* Omit<IExtensionHostConnectionResult, 'protocol'> */)));
						const initialDataChunk = Buffer.from(protocol.readEntireBuffer().buffer).toString('base64');
						protocol.dispose();
						socket.pause();
						await webSocket.drain();

						const inflateBytes = Buffer.from(webSocket.recordedInflateBytes.buffer).toString('base64');
						client.extensionHost.send({
							type: 'VSCODE_EXTHOST_IPC_SOCKET',
							initialDataChunk,
							skipWebSocketFrames: false, // TODO skipWebSocketFrames - i.e. when we connect from Node (VS Code?)
							permessageDeflate,
							inflateBytes
						} as IExtHostSocketMessage, socket);
						logService.info(`[${token}] Extension host is reconnected.`);
					}
				} else {
					logService.error(`[${token}] Unexpected connection type:`, msg.desiredConnectionType);
					safeDisposeProtocolAndSocket(protocol);
				}
			} else {
				logService.error(`[${token}] Unexpected control message:`, msg.type);
				safeDisposeProtocolAndSocket(protocol);
			}
		});
	});
	let port = 3000;
	if (args.port) {
		port = Number(args.port);
	} else if (typeof options.port === 'number') {
		port = options.port;
	}
	server.listen(port, '0.0.0.0', () => {
		const { address, port } = server.address() as net.AddressInfo;
		logService.info(`Web UI available at           https://${address}:${port}`);
	});
}
