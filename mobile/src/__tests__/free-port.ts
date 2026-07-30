/**
 * A port nobody is using.
 *
 * The integration suites each start a real Go server, and they used fixed
 * ports. That is fine until a run is killed: the harness stops the server in
 * `afterAll`, which does not run when vitest itself is killed, so the orphan
 * keeps the port. The next run's server then fails to bind and its tests
 * quietly talk to the stale one — two failures and a hang, and neither looks
 * like a port conflict from the error message.
 *
 * Asking the OS removes the failure mode instead of documenting it. There is
 * a race between releasing the probe and the server binding, which is
 * unavoidable without passing a listening socket into the child, and is
 * vanishingly unlikely against a randomly assigned high port.
 */
import { createServer } from 'node:net';

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      if (typeof address === 'string' || address === null) {
        probe.close();
        reject(new Error('could not determine a free port'));
        return;
      }
      const { port } = address;
      probe.close(() => resolve(port));
    });
  });
}
