class RsaService
  attr_accessor :private_key, :public_key, :private_key_pem,
                :public_key_pem, :type, :bits, :passphrase, :pem_key

  def initialize args = []
    args.each do |k,v|
      instance_variable_set("@#{k}", v) unless v.nil?
    end
    check_and_set_pem_files if @pem_key.present?
    init_pem_builder
    time_stamp
  end

  def bits
    @bits  || 2048
  end

  def generate
    @rsa = OpenSSL::PKey::RSA.new bits.to_i
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

  def time_stamp
    @pem_key ||= Time.parse("2012-7-31 09:38:00.000000").to_i
  end

  def cipher_encrypt
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    key_secure = @rsa.export cipher, @passphrase
  end

  def file_path(key_type)
    "rsa/#{@pem_key}_#{key_type}_key.pem"
  end

  def init_pem_builder
    @save_pem = -> (x, y) { File.open(x, 'w') {|f| f.write(y); f.path } }
  end

  def check_and_set_pem_files
    @private_key_pem = "rsa/#{@pem_key}_private_key.pem"
    @public_key_pem = "rsa/#{@pem_key}_public_key.pem"
  end
end