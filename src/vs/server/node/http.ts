import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import { ILogService } from 'vs/platform/log/common/log';
import { parse } from 'querystring';

// TODO is it enough?
const textMimeType = new Map([
	['.html', 'text/html'],
	['.js', 'text/javascript'],
	['.json', 'application/json'],
	['.css', 'text/css'],
	['.svg', 'image/svg+xml']
]);

// TODO is it enough?
const mapExtToMediaMimes = new Map([
	['.bmp', 'image/bmp'],
	['.gif', 'image/gif'],
	['.ico', 'image/x-icon'],
	['.jpe', 'image/jpg'],
	['.jpeg', 'image/jpg'],
	['.jpg', 'image/jpg'],
	['.png', 'image/png'],
	['.tga', 'image/x-tga'],
	['.tif', 'image/tiff'],
	['.tiff', 'image/tiff'],
	['.woff', 'application/font-woff']
]);

export function getMediaMime(forPath: string): string | undefined {
	const ext = path.extname(forPath);
	return mapExtToMediaMimes.get(ext.toLowerCase());
}

export function collectRequestData(request: http.IncomingMessage): Promise<Record<string, string>> {
	return new Promise(resolve => {
		const FORM_URLENCODED = 'application/x-www-form-urlencoded';
		if (request.headers['content-type'] === FORM_URLENCODED) {
			let body = '';
			request.on('data', chunk => {
				body += chunk.toString();
			});
			request.on('end', () => {
				const item = parse(body) as Record<string, string>;
				resolve(item);
			});
		}
		else {
			resolve({});
		}
	});
}

export async function serveFile(logService: ILogService, req: http.IncomingMessage, res: http.ServerResponse, filePath: string, responseHeaders: http.OutgoingHttpHeaders = {}) {
	try {

		// Sanity checks
		filePath = path.normalize(filePath); // ensure no "." and ".."

		const stat = await fs.promises.stat(filePath);

		// Check if file modified since
		const etag = `W/"${[stat.ino, stat.size, stat.mtime.getTime()].join('-')}"`; // weak validator (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag)
		if (req.headers['if-none-match'] === etag) {
			res.writeHead(304);
			return res.end();
		}

		// Headers
		responseHeaders['Content-Type'] = textMimeType.get(path.extname(filePath)) || getMediaMime(filePath) || 'text/plain';
		responseHeaders['Etag'] = etag;

		res.writeHead(200, responseHeaders);

		// Data
		fs.createReadStream(filePath).pipe(res);
	} catch (error) {
		logService.error(error.toString());
		res.writeHead(404, { 'Content-Type': 'text/plain' });
		return res.end('Not found');
	}
}

export function serveError(req: http.IncomingMessage, res: http.ServerResponse, errorCode: number, errorMessage: string): void {
	res.writeHead(errorCode, { 'Content-Type': 'text/plain' });
	res.end(errorMessage);
}
