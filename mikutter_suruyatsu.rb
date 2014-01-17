# -*- coding: utf-8 -*-
require 'twitter'
require 'base64'
require 'zlib'
require 'openssl'
require 'oauth'
require 'gtk2'

Plugin.create :mikutter_suruyatsu do
  UserConfig[:mikutter_suruyatsu_oauth_token] ||= nil
  UserConfig[:mikutter_suruyatsu_oauth_token_secret] ||= nil

  def _regenerate(file, &gen_dec)
    dec = gen_dec.call('aes-256-cbc')
    encrypted = open(file, 'rb').read
    encoded64 = Zlib::Inflate.inflate(dec.update(encrypted) + dec.final)
    Marshal.restore(Base64.decode64(encoded64))
  end

  def regenerate
    @consumer_key = _regenerate(File.expand_path(File.join(File.dirname(__FILE__), 'key'))) do |method|
      dec = OpenSSL::Cipher::Cipher.new(method)
      dec.decrypt
      dec.pkcs5_keyivgen('7778ff731a25b4dda58153e503cd2c52')
      dec
    end
    @consumer_secret = _regenerate(File.expand_path(File.join(File.dirname(__FILE__), 'secret'))) do |method|
      dec = OpenSSL::Cipher::Cipher.new(method)
      dec.decrypt
      dec.pkcs5_keyivgen('b18f92286ac7c1a0f7e66f8c7ef6b971')
      dec
    end
  end

  def get_verifier(url)

    dialog = Gtk::Dialog.new("Twitter Authentication",
                             nil,
                             nil,
                             [Gtk::Stock::OK, Gtk::Dialog::RESPONSE_ACCEPT],
                             [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_REJECT])

    label = Gtk::Label.new
    label.wrap = true
    label.set_markup("<span font_desc='20'>mikutterするやつ</span>\n\n" +
                     "まだ認証がされていません．\n" +
                     "下記URLにアクセスしてPINコードを入力して下さい．\n\n" +
                     "<a href=\"#{url}\">#{url}</a>\n\n")
    dialog.vbox.add(label)
    entry = Gtk::Entry.new
    hbox = Gtk::HBox.new(false, 10)
    hbox.pack_end(entry, false, false, 0)
    hbox.pack_end(Gtk::Label.new('PIN'), false, false, 0)
    dialog.vbox.add(hbox)
    dialog.show_all

    input = ''
    dialog.run do |response|
      case response
      when Gtk::Dialog::RESPONSE_ACCEPT
        input = entry.text
      end
      dialog.destroy
    end

    return input if input.sub(/[^0-9]/,'') =~ /^[0-9]{7}$/
    nil
  end

  def request_oauth_token
    regenerate if not defined? @consumer_key or not defined? @consumer_secret

    consumer = OAuth::Consumer.new(@consumer_key, @consumer_secret, :site => 'https://api.twitter.com')
    request_token = consumer.get_request_token 

    oauth_verifier = get_verifier(request_token.authorize_url)

    if oauth_verifier
      access_token = request_token.get_access_token(:oauth_verifier => oauth_verifier)
      if access_token
        UserConfig[:mikutter_suruyatsu_oauth_token] = access_token.token
        UserConfig[:mikutter_suruyatsu_oauth_token_secret] = access_token.secret
      end
    end
  end

  def token_registered?
    UserConfig[:mikutter_suruyatsu_oauth_token] != nil and
      UserConfig[:mikutter_suruyatsu_oauth_token_secret] != nil
  end

  def initialize
    regenerate if not defined? @consumer_key or not defined? @consumer_secret
    request_oauth_token unless token_registered?
    if token_registered? and not defined? @client
      
      if defined? Twitter::REST
        @client = Twitter::REST::Client.new do |c|
          c.consumer_key = @consumer_key
          c.consumer_secret = @consumer_secret
          c.oauth_token = UserConfig[:mikutter_suruyatsu_oauth_token]
          c.oauth_token_secret = UserConfig[:mikutter_suruyatsu_oauth_token_secret]
        end
      else
        Twitter.configure do |c|
          c.consumer_key = @consumer_key
          c.consumer_secret = @consumer_secret
          c.oauth_token = UserConfig[:mikutter_suruyatsu_oauth_token]
          c.oauth_token_secret = UserConfig[:mikutter_suruyatsu_oauth_token_secret]
        end
        @client = Twitter.client
      end
    end
  end

  command(:mikutter_suruyatsu_post,
          name: 'mikutterするやつで投稿',
          condition: lambda{ |opt| true },
          visible: true,
          role: :postbox) do |opt|
    initialize

    if defined? @client
      message = Plugin.create(:gtk).widgetof(opt.widget).widget_post.buffer.text
      Plugin.call(:before_postbox_post, message)
      Plugin.create(:gtk).widgetof(opt.widget).widget_post.buffer.text = ''

      gtk_postbox = Plugin.create(:gtk).widgetof(opt.widget)
      watch = gtk_postbox.instance_variable_get(:@watch)
      begin
        Thread.new(watch, gtk_postbox) { |w, postbox|
          if w.instance_of? Message
            @client.update(message, :in_reply_to_status_id => w.id)
            postbox.destroy
          else
            @client.update(message)
          end
        }
      rescue Exception => e
        Plugin.call(:update, nil, [Message.new(message: e.to_s, system: true)])
      end
    end
  end
  
end
