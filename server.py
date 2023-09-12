import socket
import signal
import sys
import random
import time

# Read a command line argument for the port where the server
# must run.
port = 8080
host_name = socket.gethostname()
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = f"""
   <form action = "http://{host_name}:{port}" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
"""
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = f"""
   <h1>Welcome!</h1>
   <form action="http://{host_name}:{port}" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
"""
#makes a new cookie header, returns two values
# number, header = make_new_cookie_header()
def make_new_cookie_header():
    rand_val = random.getrandbits(64)
    return rand_val, 'Set-Cookie: token=' + str(rand_val) + '\r\n'
#retrieves the cookie value from a request
#if there is no cookie it will return None
def get_cookie_from_request(request):
    for line in request.split('\n'):
        # print(line.lower())
        # print("cookie" in line.lower())
        if "cookie" in line.lower():
            split = line.split('=')
            try:
                return int(split[-1])
            except ValueError:
                return None

#### Helper functions
# Printing.
def print_value(tag, value):
    print( "Here is the", tag)
    print( "\"\"\"")
    print( value)
    print( "\"\"\"")
    print()

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# Read login credentials for all the users
# Read secret data, username and password of all the users
passwords = {}
secrets = {}
#initialize the cookies database, we will fill it later
cookies = {}
for line in open("passwords.txt", "r"):
    split_line = line.split()
    passwords[split_line[0]] = split_line[1]
for line in open("secrets.txt", "r"):
    split_line = line.split()
    secrets[split_line[0]] = split_line[1]
print(passwords, secrets)
### Loop to accept incoming HTTP connections and respond.
while True:
    time.sleep(0.1) #decreases chance connection reset
    client, addr = sock.accept()
    req = client.recv(1024).decode()

    # Let's pick the headers and entity body apart
    header_body = req.split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)

    # Send the default login page.
    html_content_to_send = login_page
    # html_content_to_send = success_page + <secret>
    # html_content_to_send = bad_creds_page
    # html_content_to_send = logout_pag e

    #headers to send
    head_send = ''

    #if logout is posted
    if body == 'action=logout':
        html_content_to_send = logout_page


    cookie_header = get_cookie_from_request(headers)
    if (cookie_header == None) and (body != 'action=logout'):
        if body[0:9] == 'username=':
            #get username and passwords
            username = ''
            password = ''
            login = body.split('&')
            username = login[0][9:]
            password = login[1][9:]

            #authenticate
            user_pass = False
            #username dne or user does not match password
            for users in passwords:
                if(users == username) and (passwords[users] == password):
                    user_pass = True
            numbers = ''
            if (username != '' and password != '') and user_pass:
                html_content_to_send = success_page + secrets[username]
                numbers, head_send = make_new_cookie_header()
                cookies[username] = numbers
                headers_to_send = head_send
            #guard black login no header
            elif username == '' and password == '':
                html_content_to_send = login_page

            elif username == '' or password == '' or (user_pass == False):
                html_content_to_send = bad_creds_page

    #header present
    if (cookie_header != None) and (body != 'action=logout'):
        valid = False
        valid_user = ''
        for users in cookies:
            if (cookies[users] == cookie_header):
                valid_user = users
                valid = True
        if valid == True:
            html_content_to_send = success_page + secrets[valid_user]
        else:
            html_content_to_send = bad_creds_page

    headers_to_send = head_send
    # Construct and send the final response
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)
    client.send(response.encode())
    client.close()

    print("Served one request/connection!")
    print()

# Close the listening socket
sock.close()
