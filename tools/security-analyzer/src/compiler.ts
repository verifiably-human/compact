/**
 * Compact Compiler Wrapper
 * Shells out to the system's `compact` compiler
 */

import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { join, basename } from 'path';
import type { CompilerOptions } from './types.js';

export class CompilerError extends Error {
  constructor(
    message: string,
    public readonly stdout: string,
    public readonly stderr: string,
    public readonly exitCode: number | null
  ) {
    super(message);
    this.name = 'CompilerError';
  }
}

/**
 * Check if compact compiler is available
 */
export async function checkCompilerAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('compact', ['--version'], {
      stdio: 'pipe',
    });

    proc.on('close', (code) => {
      resolve(code === 0);
    });

    proc.on('error', () => {
      resolve(false);
    });
  });
}

/**
 * Get compact compiler version
 */
export async function getCompilerVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const proc = spawn('compact', ['--version'], {
      stdio: 'pipe',
    });

    let stdout = '';

    proc.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    proc.on('close', (code) => {
      if (code === 0) {
        // Extract version from output like "compact 0.4.0"
        const match = stdout.match(/compact\s+([\d.]+)/);
        resolve(match ? match[1] : null);
      } else {
        resolve(null);
      }
    });

    proc.on('error', () => {
      resolve(null);
    });
  });
}

/**
 * Compile a Compact contract
 */
export async function compileContract(
  contractPath: string,
  outputDir: string,
  options: CompilerOptions = {}
): Promise<{
  success: boolean;
  stdout: string;
  stderr: string;
  duration: number;
}> {
  // Validate input
  if (!existsSync(contractPath)) {
    throw new Error(`Contract file not found: ${contractPath}`);
  }

  // Build command args
  // Note: flags must come before source and target paths
  const args = ['compile'];

  if (options.skipZk) {
    args.push('--skip-zk');
  }

  args.push(contractPath, outputDir);

  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const proc = spawn('compact', args, {
      stdio: 'pipe',
      timeout: options.timeout,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout?.on('data', (data) => {
      stdout += data.toString();
      if (options.verbose) {
        process.stdout.write(data);
      }
    });

    proc.stderr?.on('data', (data) => {
      stderr += data.toString();
      if (options.verbose) {
        process.stderr.write(data);
      }
    });

    proc.on('close', (code) => {
      const duration = Date.now() - startTime;

      if (code === 0) {
        resolve({
          success: true,
          stdout,
          stderr,
          duration,
        });
      } else {
        const error = new CompilerError(
          `Compilation failed with exit code ${code}\n\nStdout:\n${stdout}\n\nStderr:\n${stderr}`,
          stdout,
          stderr,
          code
        );
        reject(error);
      }
    });

    proc.on('error', (error) => {
      reject(
        new CompilerError(
          `Failed to spawn compiler: ${error.message}`,
          stdout,
          stderr,
          null
        )
      );
    });
  });
}

/**
 * Get the expected output directory for a contract
 */
export function getOutputDirName(contractPath: string): string {
  const name = basename(contractPath, '.compact');
  return name;
}

/**
 * Get the zkir directory path
 * The compiler outputs directly to outputDir/zkir/, not outputDir/contractName/zkir/
 */
export function getZkirDirPath(outputDir: string): string {
  return join(outputDir, 'zkir');
}
