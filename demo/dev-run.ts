#!/usr/bin/env tsx
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';

const watched = path.resolve(__dirname, 'config.ts');
let child: ChildProcess | null = null;
let restarting = false;
let debounceTimer: NodeJS.Timeout | null = null;

function start() {
  if (child) return;
  console.log('Starting demo server (runs "npm run demo")');
  const cmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  // Start detached so we can kill the whole process group on POSIX
  child = spawn(cmd, ['run', 'demo'], { stdio: 'inherit', detached: true });
  child.on('exit', (code, signal) => {
    child = null;
    if (!restarting) {
      console.log(`Demo process exited with ${signal || code}.`);
    }
  });
}

function killProcessTree(pid: number) {
  if (!pid) return;
  if (process.platform === 'win32') {
    try {
      spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
    } catch {}
  } else {
    try {
      // Negative PID kills the process group on POSIX
      process.kill(-pid, 'SIGTERM');
    } catch (e) {
      try {
        spawn('kill', ['-9', String(pid)], { stdio: 'ignore' });
      } catch {}
    }
  }
}

function stop(cb?: () => void) {
  if (!child) return cb?.();
  restarting = true;
  console.log('Stopping demo server...');

  const pid = child.pid;
  if (pid) {
    killProcessTree(pid);
  } else {
    try { child.kill(); } catch {}
  }

  const t = setTimeout(() => {
    if (child && child.pid) {
      if (process.platform === 'win32') {
        try { spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' }); } catch {}
      } else {
        try { spawn('kill', ['-9', String(child.pid)], { stdio: 'ignore' }); } catch {}
      }
    }
  }, 5000);

  child.on('exit', () => {
    clearTimeout(t);
    restarting = false;
    child = null;
    cb?.();
  });
}

function restart() {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    console.log('File change detected, restarting demo server...');
    stop(() => start());
  }, 200);
}

// Use fs.watchFile (polling) for reliable detection across editors/Windows
fs.watchFile(watched, { interval: 500 }, (curr, prev) => {
  if (curr.mtimeMs !== prev.mtimeMs) {
    restart();
  }
});

// Clean up watcher on exit
process.on('exit', () => {
  try { fs.unwatchFile(watched); } catch {}
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down...');
  stop(() => process.exit(0));
});

start();
