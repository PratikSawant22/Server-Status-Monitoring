from flask import Flask,render_template,request,redirect,url_for,session
import paramiko

isautheticate = False
user_dictionary = {}
def get_server_info(ip_address, username, password ,command):
    """
    function execute commands on remote server using paramiko
    :param ip_address: public ip address of remote server
    :param username: username of the existing user of the remote server
    :param password: password of existing user
    :param command: command which you want to execute
    :return: result of command execution and flag, flag = 1 means command is invalid and flag = 0 means command is valid
    """
    try:
        port= 22
        print("Please wait...Creating SSH Client")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(ip_address, port,username,password, timeout=3)

        print("Client created successfully")
        print("Connection with remote server")

        print("Connected.")
        print("Executing Command...")
        stdin, stdout, stderr = ssh.exec_command(command)
        iserror = 0
        error = stderr.readlines()
        if error:
            iserror = 1
            return (error, iserror )

        output = stdout.readlines()

    except paramiko.ssh_exception.AuthenticationException:
        return render_template("error.html")
    else:
        return (output, iserror)


def validate_user(ip_address , username , password):
    """
    function to validate the user of the remote server
    :param ip_address : public ip_address of remote server
    :param username : username of remote server user
    :param password: password of remote server user
    :return: TRUE or FALSE, true if user is authenticated false if user is not authenticated
    """
    port = 22
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, port,username, password, timeout=3)

    except paramiko.ssh_exception.AuthenticationException:
        print("Authentication failed, please verify your credentials: %s")
        return False
    #except Exception as e:
        # return render_template("error.html", err = str(e) )
    else:
        return True


app = Flask(__name__)

@app.route("/",methods = ['POST', 'GET'])
def index():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        username = request.form['username']
        password = request.form['password']

        user_dictionary['ip_address'] = ip_address
        user_dictionary['username'] = username
        user_dictionary['password'] = password

        flag = validate_user(ip_address,username,password)
        if flag:
            return redirect(url_for('terminal'))
        else:
            return render_template('error.html')
    else:
        return render_template("index.html")


@app.route("/terminal" ,methods = ['POST', 'GET'])
def terminal():
    ip_address = user_dictionary['ip_address']
    username = user_dictionary['username']
    password = user_dictionary['password']

    if request.method == 'POST':
        command = request.form['command']
        results, flag = get_server_info(ip_address,username,password,command)

        return render_template("terminal.html", ip = ip_address, result=results, flag=flag)

    else:
        return render_template('terminal.html',ip = ip_address)

if __name__ == "__main__" :
    app.run(debug = True)
