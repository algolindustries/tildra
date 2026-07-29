import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Two test files each spawn a real Go server and drive several devices
    // through it. Running them in parallel makes them contend for CPU and
    // ports, which shows up as timeouts that have nothing to do with the code
    // under test. Sequential is slower and honest.
    fileParallelism: false,

    // The default 5s is right for pure functions and far too tight for a test
    // that registers accounts, publishes prekeys and waits on a socket.
    testTimeout: 30_000,
    // beforeAll compiles the Go server on a cold cache.
    hookTimeout: 180_000,
  },
});
