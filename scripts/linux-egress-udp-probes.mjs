import { createSocket } from "node:dgram";
import { isIP } from "node:net";
import { tcpBypassTargets } from "./linux-egress-tcp-probes.mjs";

export function udpBypassTargets(environment) {
  return tcpBypassTargets(environment).map((target) => ({
    label: target.label.replace("raw_tcp", "raw_udp"),
    host: target.host,
    port: target.label.includes("host_") ? target.port : 8082,
    type: isIP(target.host) === 6 ? "udp6" : "udp4",
  }));
}

export function assertUdpUnreachable(label, host, port, type) {
  return new Promise((resolve, reject) => {
    const socket = createSocket(type);
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {}
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => finish(), 1500);
    socket.once("message", () => finish(new Error(`${label}_reachable`)));
    socket.once("error", () => finish());
    socket.send(
      Buffer.from("agentsecret-egress-probe"),
      port,
      host,
      (error) => {
        if (error) finish();
      },
    );
  });
}

export function listenUdpWitness(port, onReach = () => {}, onError = () => {}) {
  const sockets = [
    { socket: createSocket("udp4"), host: "0.0.0.0" },
    {
      socket: createSocket({ type: "udp6", ipv6Only: true }),
      host: "::",
    },
  ];
  const errors = [];
  const reportError = (error) => {
    errors.push(error);
    onError(error);
  };
  for (const { socket } of sockets) {
    socket.on("error", reportError);
    socket.on("message", (_message, remote) => {
      onReach();
      socket.send(
        Buffer.from("udp-witness-reached"),
        remote.port,
        remote.address,
        (error) => {
          if (error) reportError(error);
        },
      );
    });
  }

  const close = async () => {
    await Promise.all(
      sockets.map(
        ({ socket }) =>
          new Promise((resolve) => {
            try {
              socket.close(resolve);
            } catch {
              resolve();
            }
          }),
      ),
    );
  };
  const bind = (socket, bindPort, host) =>
    new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(bindPort, host, () => {
        socket.removeListener("error", reject);
        resolve(socket.address().port);
      });
    });

  return (async () => {
    try {
      const actualPort = await bind(sockets[0].socket, port, sockets[0].host);
      await bind(sockets[1].socket, actualPort, sockets[1].host);
      return { port: actualPort, errors, close };
    } catch (error) {
      await close();
      throw error;
    }
  })();
}
