import * as cp from 'child_process';
import * as http from 'http';
import { IDisposable } from 'vs/base/common/lifecycle';
import { IPCServer } from 'vs/base/parts/ipc/common/ipc';
import { ServicesAccessor } from 'vs/platform/instantiation/common/instantiation';
import { ServiceCollection } from 'vs/platform/instantiation/common/serviceCollection';
import { RemoteAgentConnectionContext } from 'vs/platform/remote/common/remoteAgentEnvironment';

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
