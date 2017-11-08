class CsrGeneratorService
  attr_reader :bits, :country, :state, :city, :department, :organization,
              :common_name, :email, :passphrase, :cipher, :digest

  def initialize(country:, state:, city:, department:, organization:,
                  common_name:, email:, bits: 4096, private_key: nil,
                  passphrase: nil, cipher: nil, digest: nil)

    cipher        ||= OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
    digest        ||= OpenSSL::Digest::SHA256.new
    @country      = country
    @state        = state
    @city         = city
    @department   = department
    @organization = organization
    @common_name  = common_name
    @email        = email
    @bits         = bits
    @passphrase   = passphrase
    @private_key  = OpenSSL::PKey::RSA.new(private_key) if private_key
    @cipher       = cipher
    @digest       = digest
  end

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.new(bits)
  end

  def request
    @request ||= OpenSSL::X509::Request.new.tap do |request|
      request.version = 0
      request.subject = OpenSSL::X509::Name.new([
        ["C",             country,      OpenSSL::ASN1::PRINTABLESTRING],
        ["ST",            state,        OpenSSL::ASN1::PRINTABLESTRING],
        ["L",             city,         OpenSSL::ASN1::PRINTABLESTRING],
        ["O",             organization, OpenSSL::ASN1::UTF8STRING],
        ["OU",            department,   OpenSSL::ASN1::UTF8STRING],
        ["CN",            common_name,  OpenSSL::ASN1::UTF8STRING],
        ["emailAddress",  email,        OpenSSL::ASN1::UTF8STRING]
      ])

      request.public_key = private_key.public_key
      request.sign(private_key, digest)
    end
  end

  def private_key_pem
    args = []

    if passphrase
      args << cipher
      args << passphrase
    end

    private_key.to_pem(*args)
  end

  def csr_pem
    request.to_pem
  end
end