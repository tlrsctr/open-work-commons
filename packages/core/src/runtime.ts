export type CommandRequest = {
  command: string;
  args: readonly string[];
  cwd: string;
};

export type CommandResult = {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  error_code?: string;
  timed_out?: boolean;
};

export interface CommandRunner {
  run(request: CommandRequest): Promise<CommandResult>;
}

export interface FileSystemProbe {
  can_access(path: string): Promise<boolean>;
}
