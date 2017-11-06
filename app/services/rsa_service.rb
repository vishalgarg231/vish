class RsaService
  attr_accessor :private_key, :public_key, :private_key_pem,
                :public_key_pem, :type, :bits, :passphrase

  def initialize args = []
    args.each do |k,v|
      instance_variable_set("@#{k}", v) unless v.nil?
    end
    init_pem_builder
  end

  def time_stamp
    @time_stamp || Time.parse("2012-7-31 09:38:00.000000").to_i
  end

  def bits
    @bits  || 2048
  end

  def generate
    @rsa = OpenSSL::PKey::RSA.new @bits.to_i
    @private_key = @passphrase.present? ? cipher_encrypt :  @rsa.to_pem
    @public_key = @rsa.public_key.to_pem
    @private_key_pem = @save_pem.call(file_path('private'), @private_key)
    @public_key_pem = @save_pem.call(file_path('public'), @public_key)
    self
  end

  def encrypt(text)
    encryptor = OpenSSL::PKey::RSA.new @public_key || File.read(@public_key_pem)
    encryptor.public_encrypt text
  end

  def decrypt(text)
    key = @private_key || File.read(@private_key_pem)
    decryptor = @passphrase.present? ? OpenSSL::PKey::RSA.new(key, @passphrase) : OpenSSL::PKey::RSA.new(key)
    decryptor.private_decrypt text
  end

  private

  def cipher_encrypt
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    key_secure = @rsa.export cipher, @passphrase
  end

  def file_path(key_type)
    "rsa/#{@time_stamp}_#{key_type}_key.pem"
  end

  def init_pem_builder
    @save_pem = -> (x, y) { File.open(x, 'w') {|f| f.write(y); f.path } }
  end
end