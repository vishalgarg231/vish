Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  get '/tools/:page' => 'tools#show'
	root 'tools#rsa'  
end
