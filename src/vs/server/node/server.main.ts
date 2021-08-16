/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Gitpod. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';
import { VSBuffer } from 'vs/base/common/buffer';
import { CancellationToken, CancellationTokenSource } from 'vs/base/common/cancellation';
import { isPromiseCanceledError, onUnexpectedError, setUnexpectedErrorHandler } from 'vs/base/common/errors';
import { Emitter, Event } from 'vs/base/common/event';
import { IDisposable } from 'vs/base/common/lifecycle';
import { FileAccess, Schemas } from 'vs/base/common/network';
import { join } from 'vs/base/common/path';
import * as platform from 'vs/base/common/platform';
import Severity from 'vs/base/common/severity';
import { ReadableStreamEventPayload } from 'vs/base/common/stream';
import { URI } from 'vs/base/common/uri';
import { IRawURITransformer, transformIncomingURIs, transformOutgoingURIs, URITransformer } from 'vs/base/common/uriIpc';
import { generateUuid } from 'vs/base/common/uuid';
import { ClientConnectionEvent, IPCServer, IServerChannel } from 'vs/base/parts/ipc/common/ipc';
import { IConfigurationService } from 'vs/platform/configuration/common/configuration';
import { ConfigurationService } from 'vs/platform/configuration/common/configurationService';
import { ExtensionHostDebugBroadcastChannel } from 'vs/platform/debug/common/extensionHostDebugIpc';
import { IDownloadService } from 'vs/platform/download/common/download';
import { DownloadService } from 'vs/platform/download/common/downloadService';
import { IEnvironmentService, INativeEnvironmentService } from 'vs/platform/environment/common/environment';
import { NativeEnvironmentService } from 'vs/platform/environment/node/environmentService';
import { ExtensionGalleryService } from 'vs/platform/extensionManagement/common/extensionGalleryService';
import { IExtensionGalleryService, IExtensionManagementService } from 'vs/platform/extensionManagement/common/extensionManagement';
import { ExtensionManagementChannel } from 'vs/platform/extensionManagement/common/extensionManagementIpc';
import { ExtensionManagementService } from 'vs/platform/extensionManagement/node/extensionManagementService';
import { ExtensionIdentifier, IExtensionDescription } from 'vs/platform/extensions/common/extensions';
import { IFileService } from 'vs/platform/files/common/files';
import { FileService } from 'vs/platform/files/common/fileService';
import { DiskFileSystemProvider } from 'vs/platform/files/node/diskFileSystemProvider';
import { SyncDescriptor } from 'vs/platform/instantiation/common/descriptors';
import { createDecorator } from 'vs/platform/instantiation/common/instantiation';
import { InstantiationService } from 'vs/platform/instantiation/common/instantiationService';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection';
import { BufferLogService } from 'vs/platform/log/common/bufferLog';
import { ConsoleMainLogger, getLogLevel, ILogService, MultiplexLogService } from 'vs/platform/log/common/log';
import { LogLevelChannel } from 'vs/platform/log/common/logIpc';
import { SpdLogLogger } from 'vs/platform/log/node/spdlogLog';
import product from 'vs/platform/product/common/product';
import { IProductService } from 'vs/platform/product/common/productService';
import { RemoteAgentConnectionContext } from 'vs/platform/remote/common/remoteAgentEnvironment';
import { IRequestService } from 'vs/platform/request/common/request';
import { RequestChannel } from 'vs/platform/request/common/requestIpc';
import { RequestService } from 'vs/platform/request/node/requestService';
import { ITelemetryService } from 'vs/platform/telemetry/common/telemetry';
import { NullTelemetryService } from 'vs/platform/telemetry/common/telemetryUtils';
import { IFileChangeDto } from 'vs/workbench/api/common/extHost.protocol';
import { Logger } from 'vs/workbench/services/extensions/common/extensionPoints';
import { ExtensionScanner, ExtensionScannerInput, IExtensionReference } from 'vs/workbench/services/extensions/node/extensionPoints';
import { IGetEnvironmentDataArguments, IRemoteAgentEnvironmentDTO, IScanExtensionsArguments, IScanSingleExtensionArguments } from 'vs/workbench/services/remote/common/remoteAgentEnvironmentChannel';
import { REMOTE_FILE_SYSTEM_CHANNEL_NAME } from 'vs/workbench/services/remote/common/remoteAgentFileSystemChannel';
import { RemoteExtensionLogFileName } from 'vs/workbench/services/remote/common/remoteAgentService';
import { args, devMode } from 'vs/server/node/args';
import { handleHttp, rawURITransformerFactory } from 'vs/server/node/server.http';
import { IServerOptions } from 'vs/server/node/server.opts';

export type IRawURITransformerFactory = (remoteAuthority: string) => IRawURITransformer;
export const IRawURITransformerFactory = createDecorator<IRawURITransformerFactory>('rawURITransformerFactory');

function registerErrorHandler(logService: ILogService): void {
	setUnexpectedErrorHandler(e => logService.error(e));
	// Print a console message when rejection isn't handled within N seconds. For details:
	// see https://nodejs.org/api/process.html#process_event_unhandledrejection
	// and https://nodejs.org/api/process.html#process_event_rejectionhandled
	const unhandledPromises: Promise<any>[] = [];
	process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
		unhandledPromises.push(promise);
		setTimeout(() => {
			const idx = unhandledPromises.indexOf(promise);
			if (idx >= 0) {
				promise.catch(e => {
					unhandledPromises.splice(idx, 1);
					if (!isPromiseCanceledError(e)) {
						logService.warn(`rejected promise not handled within 1 second: ${e}`);
						if (e && e.stack) {
							logService.warn(`stack trace: ${e.stack}`);
						}
						onUnexpectedError(reason);
					}
				});
			}
		}, 1000);
	});

	process.on('rejectionHandled', (promise: Promise<any>) => {
		const idx = unhandledPromises.indexOf(promise);
		if (idx >= 0) {
			unhandledPromises.splice(idx, 1);
		}
	});

	// Print a console message when an exception isn't handled.
	process.on('uncaughtException', function (err: Error) {
		onUnexpectedError(err);
	});
}

export async function main(options: IServerOptions): Promise<void> {
	const connectionToken = generateUuid();
	const productService = { _serviceBrand: undefined, ...product };
	const environmentService = new NativeEnvironmentService(args, productService);

	// see src/vs/code/electron-main/main.ts#142
	const bufferLogService = new BufferLogService();
	const logService = new MultiplexLogService([new ConsoleMainLogger(getLogLevel(environmentService)), bufferLogService]);
	registerErrorHandler(logService);

	// see src/vs/code/electron-main/main.ts#204
	await Promise.all<string | undefined>([
		environmentService.extensionsPath,
		environmentService.logsPath,
		environmentService.globalStorageHome.fsPath,
		environmentService.workspaceStorageHome.fsPath
	].map(path => path ? fs.promises.mkdir(path, { recursive: true }) : undefined));

	const onDidClientConnectEmitter = new Emitter<ClientConnectionEvent>();
	const channelServer = new IPCServer<RemoteAgentConnectionContext>(onDidClientConnectEmitter.event);
	channelServer.registerChannel('logger', new LogLevelChannel(logService));
	channelServer.registerChannel(ExtensionHostDebugBroadcastChannel.ChannelName, new ExtensionHostDebugBroadcastChannel());

	const fileService = new FileService(logService);
	const diskFileSystemProvider = new DiskFileSystemProvider(logService);
	fileService.registerProvider(Schemas.file, diskFileSystemProvider);

	const rootPath = FileAccess.asFileUri('', require).fsPath;
	const systemExtensionRoot = path.normalize(path.join(rootPath, '..', 'extensions'));
	const extraDevSystemExtensionsRoot = path.normalize(path.join(rootPath, '..', '.build', 'builtInExtensions'));
	const logger = new Logger((severity, source, message) => {
		const msg = devMode && source ? `[${source}]: ${message}` : message;
		if (severity === Severity.Error) {
			logService.error(msg);
		} else if (severity === Severity.Warning) {
			logService.warn(msg);
		} else {
			logService.info(msg);
		}
	});
	// see used APIs in vs/workbench/services/remote/common/remoteAgentEnvironmentChannel.ts
	class RemoteExtensionsEnvironment implements IServerChannel<RemoteAgentConnectionContext> {
		protected extensionHostLogFileSeq = 1;
		async call(ctx: RemoteAgentConnectionContext, command: string, arg?: any, cancellationToken?: CancellationToken | undefined): Promise<any> {
			if (command === 'getEnvironmentData') {
				const args: IGetEnvironmentDataArguments = arg;
				const uriTranformer = new URITransformer(rawURITransformerFactory(args.remoteAuthority));
				return transformOutgoingURIs({
					pid: process.pid,
					connectionToken,
					appRoot: URI.file(environmentService.appRoot),
					settingsPath: environmentService.machineSettingsResource,
					logsPath: URI.file(environmentService.logsPath),
					extensionsPath: URI.file(environmentService.extensionsPath),
					extensionHostLogsPath: URI.file(path.join(environmentService.logsPath, `extension_host_${this.extensionHostLogFileSeq++}`)),
					globalStorageHome: environmentService.globalStorageHome,
					workspaceStorageHome: environmentService.workspaceStorageHome,
					userHome: environmentService.userHome,
					os: platform.OS,
					marks: [],
					useHostProxy: false
				} as IRemoteAgentEnvironmentDTO, uriTranformer);
			}
			if (command === 'scanSingleExtension') {
				let args: IScanSingleExtensionArguments = arg;
				const uriTranformer = new URITransformer(rawURITransformerFactory(args.remoteAuthority));
				args = transformIncomingURIs(args, uriTranformer);
				// see scanSingleExtension in src/vs/workbench/services/extensions/electron-browser/cachedExtensionScanner.ts
				// TODO: read built nls file
				const translations = {};
				const input = new ExtensionScannerInput(product.version, product.date, product.commit, args.language, devMode, URI.revive(args.extensionLocation).fsPath, args.isBuiltin, false, translations);
				const extension = await ExtensionScanner.scanSingleExtension(input, logService);
				if (!extension) {
					return undefined;
				}
				return transformOutgoingURIs(extension, uriTranformer);
			}
			if (command === 'scanExtensions') {
				let args: IScanExtensionsArguments = arg;
				const uriTranformer = new URITransformer(rawURITransformerFactory(args.remoteAuthority));
				args = transformIncomingURIs(args, uriTranformer);
				// see _scanInstalledExtensions in src/vs/workbench/services/extensions/electron-browser/cachedExtensionScanner.ts
				// TODO: read built nls file
				const translations = {};
				let pendingSystem = ExtensionScanner.scanExtensions(new ExtensionScannerInput(product.version, product.date, product.commit, args.language, devMode, systemExtensionRoot, true, false, translations), logger);
				const builtInExtensions = product.builtInExtensions;
				if (devMode && builtInExtensions && builtInExtensions.length) {
					pendingSystem = ExtensionScanner.mergeBuiltinExtensions(pendingSystem, ExtensionScanner.scanExtensions(new ExtensionScannerInput(product.version, product.date, product.commit, args.language, devMode, extraDevSystemExtensionsRoot, true, false, translations), logger, {
						resolveExtensions: () => {
							const result: IExtensionReference[] = [];
							for (const extension of builtInExtensions) {
								result.push({ name: extension.name, path: path.join(extraDevSystemExtensionsRoot, extension.name) });
							}
							return Promise.resolve(result);
						}
					}));
				}
				const pendingUser = extensionsInstalled.then(() => ExtensionScanner.scanExtensions(new ExtensionScannerInput(product.version, product.date, product.commit, args.language, devMode, environmentService.extensionsPath, false, false, translations), logger));
				let pendingDev: Promise<IExtensionDescription[]>[] = [];
				if (args.extensionDevelopmentPath) {
					pendingDev = args.extensionDevelopmentPath.map(devPath => ExtensionScanner.scanOneOrMultipleExtensions(new ExtensionScannerInput(product.version, product.date, product.commit, args.language, devMode, URI.revive(devPath).fsPath, false, true, translations), logger));
				}
				const result: IExtensionDescription[] = [];
				const skipExtensions = new Set<string>([...args.skipExtensions.map(ExtensionIdentifier.toKey), ...(options?.skipExtensions || [])]);
				for (const extensions of await Promise.all([...pendingDev, pendingUser, pendingSystem])) {
					for (let i = extensions.length - 1; i >= 0; i--) {
						const extension = extensions[i];
						const key = ExtensionIdentifier.toKey(extension.identifier);
						if (skipExtensions.has(key)) {
							continue;
						}
						skipExtensions.add(key);
						result.unshift(transformOutgoingURIs(extension, uriTranformer));
					}
				}
				return result;
			}
			logService.error('Unknown command: RemoteExtensionsEnvironment.' + command);
			throw new Error('Unknown command: RemoteExtensionsEnvironment.' + command);
		}
		listen(ctx: RemoteAgentConnectionContext, event: string, arg?: any): Event<any> {
			logService.error('Unknown event: RemoteExtensionsEnvironment.' + event);
			throw new Error('Unknown event: RemoteExtensionsEnvironment.' + event);
		}
	}
	channelServer.registerChannel('remoteextensionsenvironment', new RemoteExtensionsEnvironment());

	// see used APIs in src/vs/workbench/services/remote/common/remoteAgentFileSystemChannel.ts
	class RemoteFileSystem implements IServerChannel<RemoteAgentConnectionContext> {
		protected readonly watchers = new Map<string, {
			watcher: DiskFileSystemProvider,
			emitter: Emitter<IFileChangeDto[] | string>
		}>();
		protected readonly watchHandles = new Map<string, IDisposable>();
		async call(ctx: RemoteAgentConnectionContext, command: string, arg?: any, cancellationToken?: CancellationToken | undefined): Promise<any> {
			if (command === 'stat') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				return diskFileSystemProvider.stat(URI.revive(uriTranformer.transformIncoming(arg[0])));
			}
			if (command === 'open') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				return diskFileSystemProvider.open(URI.revive(uriTranformer.transformIncoming(arg[0])), arg[1]);
			}
			if (command === 'close') {
				return diskFileSystemProvider.close(arg[0]);
			}
			if (command === 'read') {
				const length = arg[2];
				const data = VSBuffer.alloc(length);
				const read = await diskFileSystemProvider.read(arg[0], arg[1], data.buffer, 0, length);
				return [read, data.slice(0, read)];
			}
			if (command === 'readFile') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				const data = await diskFileSystemProvider.readFile(URI.revive(uriTranformer.transformIncoming(arg[0])));
				return VSBuffer.wrap(data);
			}
			if (command === 'write') {
				const data = arg[2] as VSBuffer;
				await diskFileSystemProvider.write(arg[0], arg[1], data.buffer, arg[3], arg[4]);
				return;
			}
			if (command === 'writeFile') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				const data = arg[1] as VSBuffer;
				await diskFileSystemProvider.writeFile(URI.revive(uriTranformer.transformIncoming(arg[0])), data.buffer, arg[2]);
				return;
			}
			if (command === 'delete') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				await diskFileSystemProvider.delete(URI.revive(uriTranformer.transformIncoming(arg[0])), arg[1]);
				return;
			}
			if (command === 'mkdir') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				await diskFileSystemProvider.mkdir(URI.revive(uriTranformer.transformIncoming(arg[0])));
				return;
			}
			if (command === 'readdir') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				return diskFileSystemProvider.readdir(URI.revive(uriTranformer.transformIncoming(arg[0])));
			}
			if (command === 'rename') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				return diskFileSystemProvider.rename(
					URI.revive(uriTranformer.transformIncoming(arg[0])),
					URI.revive(uriTranformer.transformIncoming(arg[1])),
					arg[2]
				);
			}
			if (command === 'copy') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				return diskFileSystemProvider.copy(
					URI.revive(uriTranformer.transformIncoming(arg[0])),
					URI.revive(uriTranformer.transformIncoming(arg[1])),
					arg[2]
				);
			}
			if (command === 'watch') {
				const watcher = this.watchers.get(arg[0])?.watcher;
				if (watcher) {
					const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
					const unwatch = watcher.watch(URI.revive(uriTranformer.transformIncoming(arg[2])), arg[3]);
					this.watchHandles.set(
						arg[0] + ':' + arg[1],
						unwatch
					);
				} else {
					logService.error(`'filechange' event should be called before 'watch' first request`);
				}
				return;
			}
			if (command === 'unwatch') {
				this.watchHandles.get(arg[0] + ':' + arg[1])?.dispose();
				this.watchHandles.delete(arg[0] + ':' + arg[1]);
				return;
			}
			logService.error('Unknown command: RemoteFileSystem.' + command);
			throw new Error('Unknown command: RemoteFileSystem.' + command);
		}
		protected obtainFileChangeEmitter(ctx: RemoteAgentConnectionContext, session: string): Emitter<IFileChangeDto[] | string> {
			let existing = this.watchers.get(session);
			if (existing) {
				return existing.emitter;
			}
			const watcher = new DiskFileSystemProvider(logService);
			const emitter = new Emitter<IFileChangeDto[] | string>({
				onLastListenerRemove: () => {
					this.watchers.delete(session);
					emitter.dispose();
					watcher.dispose();
					logService.info(`[session:${session}] closed watching fs`);
				}
			});
			logService.info(`[session:${session}] started watching fs`);
			this.watchers.set(session, { watcher, emitter });

			const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
			watcher.onDidChangeFile(changes => emitter.fire(
				changes.map(change => ({
					resource: uriTranformer.transformOutgoingURI(change.resource),
					type: change.type
				} as IFileChangeDto))
			));
			watcher.onDidErrorOccur(error => emitter.fire(error));
			return emitter;
		}
		listen(ctx: RemoteAgentConnectionContext, event: string, arg?: any): Event<any> {
			if (event === 'filechange') {
				return this.obtainFileChangeEmitter(ctx, arg[0]).event;
			}
			if (event === 'readFileStream') {
				const uriTranformer = new URITransformer(rawURITransformerFactory(ctx.remoteAuthority));
				const resource = URI.revive(transformIncomingURIs(arg[0], uriTranformer));
				const emitter = new Emitter<ReadableStreamEventPayload<VSBuffer>>({
					onLastListenerRemove: () => {
						cancellationTokenSource.cancel();
					}
				});
				const cancellationTokenSource = new CancellationTokenSource();
				const stream = diskFileSystemProvider.readFileStream(resource, arg[1], cancellationTokenSource.token);
				stream.on('data', data => emitter.fire(VSBuffer.wrap(data)));
				stream.on('error', error => emitter.fire(error));
				stream.on('end', () => {
					emitter.fire('end');
					emitter.dispose();
					cancellationTokenSource.dispose();
				});
				return emitter.event;
			}
			logService.error('Unknown event: RemoteFileSystem.' + event);
			throw new Error('Unknown event: RemoteFileSystem.' + event);
		}
	}
	channelServer.registerChannel(REMOTE_FILE_SYSTEM_CHANNEL_NAME, new RemoteFileSystem());

	// Init services
	const services = new ServiceCollection();
	services.set(IRawURITransformerFactory, rawURITransformerFactory);

	services.set(IEnvironmentService, environmentService);
	services.set(INativeEnvironmentService, environmentService);
	services.set(ILogService, logService);
	services.set(ITelemetryService, NullTelemetryService);

	services.set(IFileService, fileService);

	services.set(IConfigurationService, new SyncDescriptor(ConfigurationService, [environmentService.settingsResource, fileService]));
	services.set(IProductService, productService);
	services.set(IRequestService, new SyncDescriptor(RequestService));
	services.set(IDownloadService, new SyncDescriptor(DownloadService));

	services.set(IExtensionGalleryService, new SyncDescriptor(ExtensionGalleryService));
	services.set(IExtensionManagementService, new SyncDescriptor(ExtensionManagementService));

	services.set(IRequestService, new SyncDescriptor(RequestService));

	if (options.configure) {
		options.configure(services, channelServer);
	}

	let resolveExtensionsInstalled: (value?: unknown) => void;
	const extensionsInstalled = new Promise(resolve => resolveExtensionsInstalled = resolve);

	// Startup
	const instantiationService = new InstantiationService(services);
	instantiationService.invokeFunction(accessor => {
		let startResult = undefined;
		if (options.start) {
			startResult = options.start(accessor, channelServer);
		}
		if (startResult && startResult.installingInitialExtensions) {
			startResult.installingInitialExtensions.then(resolveExtensionsInstalled);
		} else {
			resolveExtensionsInstalled();
		}

		const extensionManagementService = accessor.get(IExtensionManagementService);
		channelServer.registerChannel('extensions', new ExtensionManagementChannel(extensionManagementService, requestContext => new URITransformer(rawURITransformerFactory(requestContext))));
		(extensionManagementService as ExtensionManagementService).removeDeprecatedExtensions();

		const requestService = accessor.get(IRequestService);
		channelServer.registerChannel('request', new RequestChannel(requestService));

		// Delay creation of spdlog for perf reasons (https://github.com/microsoft/vscode/issues/72906)
		bufferLogService.logger = new SpdLogLogger('main', join(environmentService.logsPath, `${RemoteExtensionLogFileName}.log`), true, bufferLogService.getLevel());

		handleHttp({
			serverOptions: options,
			instantiationService,
			logService,
			environmentService,
			onDidClientConnectEmitter,
			channelServer
		});
	});
}
