class ToolsController < ApplicationController
  protect_from_forgery with: :exception

  def show
  	@response = RsaService.new.generate
  	render template: "tools/#{params[:page]}"
  end
end
