class DsaService
  attr_accessor :private_key, :public_key, :private_key_pem,
                :public_key_pem, :type, :bits, :passphrase, :pem_key, :passphrase_pem

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
    @dsa = OpenSSL::PKey::DSA.new bits.to_i
    @private_key = @passphrase.present? ? cipher_encrypt :  @dsa.to_pem
    @public_key = @dsa.public_key.to_pem
    @private_key_pem = @save_pem.call(file_path('private'), @private_key)
    @public_key_pem = @save_pem.call(file_path('public'), @public_key)
    @passphrase_pem = @save_pem.call(file_path('passphrase'), @passphrase) if @passphrase.present?
    self
  end

  def sign(text)
    digest = OpenSSL::Digest::SHA1.digest(text)
    sig = @dsa.syssign(digest)
  end

  def verify_sign(text, sign)
    key = @private_key || File.read(@private_key_pem)
    @dsa = @passphrase.present? ? OpenSSL::PKey::DSA.new(key, @passphrase) : OpenSSL::PKey::DSA.new(key)
    digest = OpenSSL::Digest::SHA1.digest(text)
    @dsa.sysverify(digest, sign)
  end

  private

  def time_stamp
    @pem_key ||= SecureRandom.hex(10) + (Time.now).to_i.to_s
  end

  def cipher_encrypt
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    key_secure = @dsa.export cipher, @passphrase
  end

  def file_path(key_type)
    "dsa/#{@pem_key}_#{key_type}_key.pem"
  end

  def init_pem_builder
    @save_pem = -> (x, y) { File.open(x, 'w') {|f| f.write(y); f.path } }
  end

  def check_and_set_pem_files
    @private_key_pem = "dsa/#{@pem_key}_private_key.pem"
    @public_key_pem = "dsa/#{@pem_key}_public_key.pem"
    passphrase_pem = "dsa/#{@pem_key}_passphrase_key.pem" 
    if File.exist?(passphrase_pem)
      @passphrase_pem = passphrase_pem
      @passphrase = File.read(passphrase_pem)
    end
  end
end