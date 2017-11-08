class SelfSignedCertService
  attr_accessor :self_signed_pem, :private_key

  def initialize(params = {})
    @country = params[:country] || 'US'
    @state = params[:state] || 'CA'
    @locality = params[:locality] || 'Mountain View'
    @common_name = params[:common_name] || 'SecureForward CA'
  end

  def generate
    @key = OpenSSL::PKey::RSA.new(1024)
    public_key = @key.public_key

    @cert = OpenSSL::X509::Certificate.new
    @cert.subject = @cert.issuer = OpenSSL::X509::Name.parse(subject)
    @cert.not_before = Time.now
    @cert.not_after = Time.now + 365 * 24 * 60 * 60
    @cert.public_key = public_key
    @cert.serial = 0x0
    @cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = @cert
    ef.issuer_certificate = @cert
    @cert.extensions = [
        ef.create_extension("basicConstraints","CA:TRUE", true),
        ef.create_extension("subjectKeyIdentifier", "hash")
    ]
    @cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                           "keyid:always,issuer:always")

    @cert.sign @key, OpenSSL::Digest::SHA1.new
    @self_signed_pem = @cert.to_pem
    @private_key = @key.to_s
    self
  end

  private

  def subject
    "/C=#{@country}/ST=#{@state}/L=#{@locality}/CN=#{@common_name}"
  end
end
