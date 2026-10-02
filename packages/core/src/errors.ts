/** Fixed public error codes only: never expose private paths, credentials or OS errors. */
export class NasError extends Error {
  constructor(public readonly code:string){super(code);}
}
