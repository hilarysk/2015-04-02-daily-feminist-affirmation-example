Dailyfemaff::Application.routes.draw do
  
  
  # NOTES:
  #
  # ------------- LINE 140 IN EXCERPTS CONTROLLER: USE METHOD FOR PRE-SELECTING DROPDOWN -------------
  #
  # - Parallax?
  # - code video describing tagging process for THIS site
  # - Design - more gray boxes, more hover with checkboxes, fewer dropdowns for display where possible
  # - Test that putting in bad info doesn't work and displays errors properly
  # - Make so when click submit buttons, partial 'display' changes instead of loading partial (cleaner, doesn't reload page)
  # - Add so admins can see all of particular item (already exists in search, but still)
  # - Make so yay item.sample requires one database call instead of four
  # - Pull out the auto-keyword tagging into method
  # - Make it so admin layout menu includes public options; have so admin or public menu displays based on if someone is logged in.
  # - When updating an excerpt, have the original person name/id be the first select option
  # - responsive using @media/@screens / break points?
  
  ##################################################
  
  # PUBLIC
  
  root :to => 'public#home'
  
  get "home" => 'public#home'
  
  get "yay" => 'public#yay'
  
  get "whoops" => 'public#whoops' # <-- this refers to the controller, not the view
  
  get "about" => 'public#about'
  
  get "search" => 'public#search'
  
  get "keyword" => 'public#keyword'
  
  get "item" => 'public#item'
  
  ##################################################
  
  # ADMIN GENERAL
  
  get "admin/inactive" => 'admin#inactive'
  
  get "login" => 'admin#login'
  
  post "login" => 'application#user_verify'
  
  get "logout" => 'application#logout'
  
  get "admin/contrib" => 'admin#contrib'
  
  get "admin/update_database" => 'admin#update_database' # --> change to "library" instead of "database"
  
  ##################################################
  
  # ADMIN EXCERPT
    
  # This shows the form to create a new excerpt  
  
  get "admin/excerpts/new" => 'excerpts#new'
  
  # This saves the new excerpt; no route name.
  
  post "admin/excerpts" => 'excerpts#create', as: "excerpts"
  
  # This lets you choose which excerpt to edit.
  
  get "admin/excerpts/update" => 'excerpts#update_find'
  
  # This grabs the id for the excerpt the user wants to update and redirects to the proper edit path
  
  post "admin/excerpts/update_choice" => 'excerpts#update_choice'
  
  # This shows the edit form for the excerpt.
  
  get "admin/excerpts/:id/edit" => 'excerpts#edit'
  
  # This updates the excerpt and saves the edit form data
  
  put "admin/excerpts/:id" => 'excerpts#update'
  
  # This lets you choose which excerpt to delete.
  
  get "admin/excerpts/delete" => 'excerpts#delete_find'
  
  # This grabs the id for the excerpt the user wants to delete and redirects the user to the confirm page
  
  post "admin/excerpts/delete_choice" => 'excerpts#delete_choice'
  
  # This is the confirmation page for the user re: deleting
  
  get "admin/excerpts/:id/delete" => 'excerpts#deleteconfirm'
  
  # This deletes the excerpt.
  
  delete "admin/excerpts/:id" => 'excerpts#delete'
  
  ##################################################
  
  # ADMIN QUOTE

  # This shows the form to create a new quote

  get "admin/quotes/new" => 'quotes#new'

  # This saves the new quote; no route name.

  post "admin/quotes" => 'quotes#create', as: "quotes"

  # This lets you choose which quote to edit.

  get "admin/quotes/update" => 'quotes#update_find'
  
  # This grabs the id for the quote the user wants to update and redirects to the proper edit path
  
  post "admin/quotes/update_choice" => 'quotes#update_choice'

  # This shows the edit form for the quote.

  get "admin/quotes/:id/edit" => 'quotes#edit'

  # This updates the quote and saves the edit form data

  put "admin/quotes/:id" => 'quotes#update'
  
  # This lets you choose which quote to delete.
  
  get "admin/quotes/delete" => 'quotes#delete_find'
  
  # This grabs the id for the quote the user wants to delete and redirects the user to the confirm page
  
  post "admin/quotes/delete_choice" => 'quotes#delete_choice'
  
  # This is the confirmation page for the user re: deleting
  
  get "admin/quotes/:id/delete" => 'quotes#deleteconfirm'
  
  # This deletes the quote.
  
  delete "admin/quotes/:id" => 'quotes#delete'
  
  ##################################################
  
  # ADMIN TERM

  # This shows the form to create a new term

  get "admin/terms/new" => 'terms#new'

  # This saves the new term; no route name.

  post "admin/terms" => 'terms#create', as: "terms"

  # This lets you choose which term to edit.

  get "admin/terms/update" => 'terms#update_find'
  
  # This grabs the id for the term the user wants to update and redirects to the proper edit path
  
  post "admin/terms/update_choice" => 'terms#update_choice'

  # This shows the edit form for the term.

  get "admin/terms/:id/edit" => 'terms#edit'

  # This updates the term and saves the edit form data

  put "admin/terms/:id" => 'terms#update'
  
  # This lets you choose which term to delete.
  
  get "admin/terms/delete" => 'terms#delete_find'
  
  # This grabs the id for the term the user wants to delete and redirects the user to the confirm page
  
  post "admin/terms/delete_choice" => 'terms#delete_choice'
  
  # This is the confirmation page for the user re: deleting
  
  get "admin/terms/:id/delete" => 'terms#deleteconfirm'
  
  # This deletes the term.
  
  delete "admin/terms/:id" => 'terms#delete'
  
  ##################################################
  
  # ADMIN PERSON
  
  # This shows the form to create a new person

  get "admin/people/new" => 'people#new'

  # This saves the new person; no route name.

  post "admin/people" => 'people#create', as: "people"

  # This lets you choose which person to edit.

  get "admin/people/update" => 'people#update_find'
  
  # This grabs the id for the person the user wants to update and redirects to the proper edit path
  
  post "admin/people/update_choice" => 'people#update_choice'

  # This shows the edit form for the person.

  get "admin/people/:id/edit" => 'people#edit'

  # This updates the person and saves the edit form data

  put "admin/people/:id" => 'people#update'
  
  # This lets you choose which person to delete.
  
  get "admin/people/delete" => 'people#delete_find'
  
  # This grabs the id for the person the user wants to delete and redirects the user to the confirm page
  
  post "admin/people/delete_choice" => 'people#delete_choice'
  
  # This is the confirmation page for the user re: deleting
  
  get "admin/people/:id/delete" => 'people#deleteconfirm'
  
  # This deletes the person.
  
  delete "admin/people/:id" => 'people#delete'
    
  ##################################################

  # ADMIN KEYWORD

  # This shows the form to create a new keyword

  get "admin/keywords/new" => 'keywords#new'

  # This saves the new keyword; no route name.

  post "admin/keywords" => 'keywords#create', as: "keywords"

  # This lets you choose which keyword to edit.

  get "admin/keywords/update" => 'keywords#update_find'
  
  # This grabs the id for the keyword the user wants to update and redirects to the proper edit path
  
  post "admin/keywords/update_choice" => 'keywords#update_choice'

  # This shows the edit form for the keyword.

  get "admin/keywords/:id/edit" => 'keywords#edit'

  # This updates the keyword and saves the edit form data

  put "admin/keywords/:id" => 'keywords#update'
  
  # This lets you choose which keyword to delete.
  
  get "admin/keywords/delete" => 'keywords#delete_find'
  
  # This grabs the id for the keyword the user wants to delete and redirects the user to the confirm page
  
  post "admin/keywords/delete_choice" => 'keywords#delete_choice'
  
  # This is the confirmation page for the user re: deleting
  
  get "admin/keywords/:id/delete" => 'keywords#deleteconfirm'
  
  # This deletes the keyword.
  
  delete "admin/keywords/:id" => 'keywords#delete'
    
  ##################################################
  
  # # ADMIN KEYWORDITEM
  
  # This shows the form to create a new keyworditem  

  get "admin/tags/change" => 'keyword_items#choose'
  
  # This actually adds or deletes the keyworditems
  
  post "admin/tags" => 'keyword_items#change'
  
  ##################################################

  # ADMIN USER
  
  # -----------------------------------------------
  # MUST HAVE PRIVILEGE OF 1

  # This shows the form to create a new user

  get "admin/users/new" => 'users#new'

  # This saves the new user; no route name.

  post "admin/users" => 'users#create', as: "users"
  
  # This lets you choose which user to edit.

  get "admin/users/update" => 'users#update_find'

  # This grabs the id for the user the user wants to update and redirects to the proper edit path

  post "admin/users/update_choice" => 'users#update_choice'
  
  # -----------------------------------------------

  # This shows the edit form for the user.

  get "admin/users/:id/edit" => 'users#edit'

  # This updates the user and saves the edit form data
  
  ##################################################################

  put "admin/users/:id" => 'users#update'  #include session check for this method so that only works if params["id"] matches session["user_id"]
  
  ################################################################2

  # This lets you choose which user to delete.

  get "admin/users/delete" => 'users#delete_find'

  # This grabs the id for the user the user wants to delete and redirects the user to the confirm page

  post "admin/users/delete_choice" => 'users#delete_choice'

  # This is the confirmation page for the user re: deleting

  get "admin/users/:id/delete" => 'users#deleteconfirm'

  # This deletes the user.

  delete "admin/users/:id" => 'users#delete'
  
  ##################################################
  
  # MATCHES
  
  match "/admin/*path" => 'admin#coming_soon'
  
  match '*path' => 'public#whoops'
  
  
  # The priority is based upon order of creation:
  # first created -> highest priority.

  # Sample of regular route:
  #   match 'products/:id' => 'catalog#view'
  # Keep in mind you can assign values other than :controller and :action

  # Sample of named route:
  #   match 'products/:id/purchase' => 'catalog#purchase', :as => :purchase
  # This route can be invoked with purchase_url(:id => product.id)

  # Sample resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Sample resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Sample resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Sample resource route with more complex sub-resources
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', :on => :collection
  #     end
  #   end

  # Sample resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end

  # You can have the root of your site routed with "root"
  # just remember to delete public/index.html.
  # root :to => 'welcome#index'

  # See how all your routes lay out with "rake routes"

  # This is a legacy wild controller route that's not recommended for RESTful applications.
  # Note: This route will make all actions in every controller accessible via GET requests.
  # match ':controller(/:action(/:id))(.:format)'
end
