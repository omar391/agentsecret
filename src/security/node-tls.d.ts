declare module "node:tls" {
  export interface TLSSocket {
    authorized: boolean;
    alpnProtocol: string | false | null;
    destroy(): this;
    write(data: string): boolean;
    setTimeout(timeout: number, callback?: () => void): this;
    on(event: "data", listener: (chunk: Uint8Array) => void): this;
    on(event: "end", listener: () => void): this;
    on(event: "close", listener: () => void): this;
    on(event: "error", listener: (error: Error) => void): this;
  }
  export function connect(
    options: {
      host: string;
      port: number;
      servername?: string;
      rejectUnauthorized: true;
      ALPNProtocols: string[];
      timeout: number;
    },
    callback: () => void,
  ): TLSSocket;
}
