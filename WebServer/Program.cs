using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

const int DefaultSSLPort = 443;
//const string Default404HTML = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 - Resource Not Found</h1><p>The page or resource could not be found.</p></body></html>";
const string DefaultHTML = "<!DOCTYPE html><html><head><title>An Example Page</title></head><body><p>Hello World, this is a very simple HTML document.</p></body></html>";

Console.WriteLine("Blingking01's simple HTTPS web server.");
Console.WriteLine("Type STOP or QUIT to stop server.");
Console.WriteLine();

Socket? listener = null;
bool listening = false;

string? line;
string cmd;
string[] pars;
while ((line = Console.ReadLine())?.ToUpper() != "QUIT")
{
    if (string.IsNullOrEmpty(line))
        continue;

    cmd = line;
    pars = cmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    cmd = pars[0].ToUpper();

    if (cmd == "HELP")
    {
        Console.WriteLine("Available commands:");
        Console.WriteLine("  HELP - Prints this comand quide,");
        Console.WriteLine("  START [IPAddress:Port (optional)] - Starts the web server, if a IP address : port has NOT been specified, the server will be started using the first available Internetwork addaptor or the Loopback address,");
        Console.WriteLine("  STOP - Stops the server without closing the program,");
        Console.WriteLine("  QUIT - Stops the server if running and closes the program,");
    }
    else if (cmd == "STOP")
        StopServer();
    else if (cmd == "START")
    {
        IPEndPoint? localep = new(GetLocalIPv4Address(), DefaultSSLPort);
        if (pars.Length > 1)
            if (!IPEndPoint.TryParse(pars[1], out localep))
            {
                Console.WriteLine("Invalid argument for START, expected IP address and/or port.");
                return;
            }

        StartServer(localep);
    }
    else
        Console.WriteLine($"{cmd} is not a valid command, type HELP to see a list of available commands.");
};

StopServer();

IPAddress GetLocalIPv4Address()
{
    string hostname = Dns.GetHostName();
    IPAddress address = Dns.GetHostAddresses(hostname).FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork, IPAddress.Loopback);

    return address;
}

void StartServer(IPEndPoint localep)
{
    if (listening)
    {
        Console.WriteLine("Cannot start server, server is already running.");
        return;
    }

    listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    listener.Bind(localep);
    listener.Listen();
    listening = true;
    Console.WriteLine($"Server started @ {listener.LocalEndPoint}.");

    listener.BeginAccept(AcceptClient, null);
}

void StopServer()
{
    listening = false;
    listener?.Close();
    listener = null;
    Console.WriteLine("Server stopped.");
}

void AcceptClient(IAsyncResult result)
{
    if (!listening)
        return;

    Socket client = listener.EndAccept(result);

    // Begin accepting a new connection so the server continues to serve new requests...
    listener.BeginAccept(AcceptClient, null);

    using NetworkStream netStream = new(client);

    // Set up SSL so that we can support multiple hosts each with their own certificate (virtual hosting)...
    using SslStream sslStream = new(netStream);
    SslServerAuthenticationOptions sslAuthOptions = new()
    {
        // Enable TLS which includes the ability to broadcast the desired hostname before authentication...
        EnabledSslProtocols = SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13,

        // To do so we need to select the correct certificate during the client/server authentication...
        ServerCertificateSelectionCallback = new ServerCertificateSelectionCallback(ServerCertificateSelectionCallback)
    };
    sslStream.AuthenticateAsServer(sslAuthOptions);

    using StreamReader reader = new(sslStream, true);
    string? req = reader.ReadLine();
    Console.WriteLine($"Request received from {client.RemoteEndPoint},\r\n  {req}.");
    // There would also be various headers to come and maybe POST data too.

    // Send a response to the user-agent...
    using StreamWriter writer = new(sslStream, new UTF8Encoding(false));
    // Send 200 OK to the user-agent...
    writer.WriteLine("HTTP/1.1 200 OK");
    // Send our headers to the user-agent...
    writer.WriteLine($"Date: {DateTime.Now:R}");
    writer.WriteLine("Content-Type: text/html; charset=UTF-8");
    // Conent-Length is important and is the length of the html data your sending...
    writer.WriteLine($"Content-Length: {DefaultHTML.Length}");
    writer.WriteLine($"Last-Modified: {DateTime.Now:R}");
    writer.WriteLine("Server: Blingking01's HTTPS web server version 1.0");
    writer.WriteLine("Connection: close");
    writer.WriteLine();
    // Send html content after the blank line with no line return...
    writer.Write(DefaultHTML);
}

X509Certificate ServerCertificateSelectionCallback(object sender, string? hostName)
{
    if (string.IsNullOrEmpty(hostName))
        throw new NotSupportedException("Could not determine hostname and cannot serve a certificate.");

    // Here we take a look at the hostname and select a certificate that matches the hostname,
    // All web domains need to have their own certificate.

    // To create a certificate for your web domain try:
    // In windows powershell type ' New-SelfSignedCertificate -DnsName @("my.webdomain.local", "www.my.webdomain.local") -CertStoreLocation "cert:\LocalMachine\My" '
    // Where my.webdomain.local is the domain of your website, usualy you would modify your hosts file to match this domain to your system.

    using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);

    X509Certificate2 certificate = store.Certificates.First(cert => cert.Subject == $"CN={hostName}");
    return certificate;
}