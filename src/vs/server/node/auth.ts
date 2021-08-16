import * as http from 'http';
import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import { ServerParsedArgs } from 'vs/server/node/args';
import { serveError } from 'vs/server/node/http';

/** Ensures that the input is sanitized by checking
 * - it's a string
 * - greater than 0 characters
 * - trims whitespace
 */
export function sanitizeString(str: string): string {
	// Very basic sanitization of string
	// Credit: https://stackoverflow.com/a/46719000/3015595
	return typeof str === 'string' && str.trim().length > 0 ? str.trim() : '';
}

export const ensureAuthenticated = async (args: ServerParsedArgs, req: http.IncomingMessage, res: http.ServerResponse): Promise<boolean> => {
	const isAuthenticated = await authenticated(args, req);
	if (!isAuthenticated) {
		serveError(req, res, 401, 'Unauthorized');
	}
	return isAuthenticated;
};

/**
 * Return true if authenticated via cookies.
 */
export const authenticated = async (args: ServerParsedArgs, req: http.IncomingMessage): Promise<boolean> => {
	if (!args.password && !args.hashedPassword) {
		return true;
	}
	const passwordMethod = getPasswordMethod(args.hashedPassword);
	const cookies = parseCookies(req);
	const isCookieValidArgs: IsCookieValidArgs = {
		passwordMethod,
		cookieKey: sanitizeString(cookies.key),
		passwordFromArgs: args.password || '',
		hashedPasswordFromArgs: args.hashedPassword,
	};

	return await isCookieValid(isCookieValidArgs);
};

function parseCookies(request: http.IncomingMessage): Record<string, string> {
	const cookies: Record<string, string> = {},
		rc = request.headers.cookie;

	// eslint-disable-next-line code-no-unused-expressions
	rc && rc.split(';').forEach(cookie => {
		let parts = cookie.split('=');
		if (parts.length > 0) {
			const name = parts.shift()!.trim();
			let value = decodeURI(parts.join('='));
			value = value.substring(1, value.length - 1);
			cookies[name] = value;
		}
	});

	return cookies;
}

export type PasswordMethod = 'ARGON2' | 'PLAIN_TEXT';

/**
 * Used to determine the password method.
 *
 * There are three options for the return value:
 * 1. "SHA256" -> the legacy hashing algorithm
 * 2. "ARGON2" -> the newest hashing algorithm
 * 3. "PLAIN_TEXT" -> regular ol' password with no hashing
 *
 * @returns "ARGON2" | "PLAIN_TEXT"
 */
export function getPasswordMethod(hashedPassword: string | undefined): PasswordMethod {
	if (!hashedPassword) {
		return 'PLAIN_TEXT';
	}
	return 'ARGON2';
}

type PasswordValidation = {
	isPasswordValid: boolean
	hashedPassword: string
};

type HandlePasswordValidationArgs = {
	/** The PasswordMethod */
	passwordMethod: PasswordMethod
	/** The password provided by the user */
	passwordFromRequestBody: string
	/** The password set in PASSWORD or config */
	passwordFromArgs: string | undefined
	/** The hashed-password set in HASHED_PASSWORD or config */
	hashedPasswordFromArgs: string | undefined
};

function safeCompare(a: string, b: string): boolean {
	if (b.length > a.length) {
		a = a.padEnd(b.length);
	}
	if (a.length > b.length) {
		b = b.padEnd(a.length);
	}
	return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export const generatePassword = async (length = 24): Promise<string> => {
	const buffer = Buffer.alloc(Math.ceil(length / 2));
	await new Promise(resolve => {
		crypto.randomFill(buffer, (_, buf) => resolve(buf));
	});
	return buffer.toString('hex').substring(0, length);
};

/**
 * Used to hash the password.
 */
export const hash = async (password: string): Promise<string> => {
	try {
		return await argon2.hash(password);
	} catch (error) {
		console.error(error);
		return '';
	}
};

/**
 * Used to verify if the password matches the hash
 */
export const isHashMatch = async (password: string, hash: string) => {
	if (password === '' || hash === '' || !hash.startsWith('$')) {
		return false;
	}
	try {
		return await argon2.verify(hash, password);
	} catch (error) {
		throw new Error(error);
	}
};

/**
 * Used to hash the password using the sha256
 * algorithm. We only use this to for checking
 * the hashed-password set in the config.
 *
 * Kept for legacy reasons.
 */
export const hashLegacy = (str: string): string => {
	return crypto.createHash('sha256').update(str).digest('hex');
};

/**
 * Used to check if the password matches the hash using
 * the hashLegacy function
 */
export const isHashLegacyMatch = (password: string, hashPassword: string) => {
	const hashedWithLegacy = hashLegacy(password);
	return safeCompare(hashedWithLegacy, hashPassword);
};

/**
 * Checks if a password is valid and also returns the hash
 * using the PasswordMethod
 */
export async function handlePasswordValidation({
	passwordMethod,
	passwordFromArgs,
	passwordFromRequestBody,
	hashedPasswordFromArgs,
}: HandlePasswordValidationArgs): Promise<PasswordValidation> {
	const passwordValidation: PasswordValidation = {
		isPasswordValid: false,
		hashedPassword: '',
	};

	switch (passwordMethod) {
		case 'PLAIN_TEXT': {
			const isValid = passwordFromArgs ? safeCompare(passwordFromRequestBody, passwordFromArgs) : false;
			passwordValidation.isPasswordValid = isValid;

			const hashedPassword = await hash(passwordFromRequestBody);
			passwordValidation.hashedPassword = hashedPassword;
			break;
		}
		case 'ARGON2': {
			const isValid = await isHashMatch(passwordFromRequestBody, hashedPasswordFromArgs || '');
			passwordValidation.isPasswordValid = isValid;

			passwordValidation.hashedPassword = hashedPasswordFromArgs || '';
			break;
		}
		default:
			break;
	}

	return passwordValidation;
}

export type IsCookieValidArgs = {
	passwordMethod: PasswordMethod
	cookieKey: string
	hashedPasswordFromArgs: string | undefined
	passwordFromArgs: string | undefined
};

/** Checks if a req.cookies.key is valid using the PasswordMethod */
export async function isCookieValid({
	passwordFromArgs = '',
	cookieKey,
	hashedPasswordFromArgs = '',
	passwordMethod,
}: IsCookieValidArgs): Promise<boolean> {
	let isValid = false;
	switch (passwordMethod) {
		case 'PLAIN_TEXT':
			isValid = await isHashMatch(passwordFromArgs, cookieKey);
			break;
		case 'ARGON2':
			isValid = safeCompare(cookieKey, hashedPasswordFromArgs);
			break;
		default:
			break;
	}
	return isValid;
}
