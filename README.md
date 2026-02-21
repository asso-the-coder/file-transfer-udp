# file-transfer-udp
Server and client code for a file transfer system over UDP with Stop-and-Wait ARQ for any file type and size.

To run:
1. Clone the client directory onto a client (sender) machine
2. Clone the server directory onto a server (receiver) machine
3. Run the server program (any unused port number will work)
4. Run the client program (make sure you have the server IP address and port number from step #3)
5. Enter the file path as instructed on the client side

And that's it! You successfully (and reliably-ish) transfered files between two machines. Swap client and server to send the other way. 