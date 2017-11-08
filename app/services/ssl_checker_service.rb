require "net/https"

class SslCheckerService

  attr_reader :valid_on, :valid_until, :issuer, :valid, :errors

  def test host
    tcp_client = TCPSocket.new(host, 443)
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.hostname = host
    ssl_client.connect
    cert = OpenSSL::X509::Certificate.new(ssl_client.peer_cert)
    ssl_client.sysclose
    tcp_client.close

    certprops = OpenSSL::X509::Name.new(cert.issuer).to_a
    issuer = certprops.select { |name, data, type| name == "O" }.first[1]
    results = { 
      valid_on: cert.not_before,
      valid_until: cert.not_after,
      issuer: issuer,
      valid: (ssl_client.verify_result == 0)
    }
    self
  rescue Exception => e
    @errors = "SSL certificate test failed: #{e.message}"
    self
  end
end

