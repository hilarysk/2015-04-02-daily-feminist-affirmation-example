class UsersController < ApplicationController  
  layout "admin"
 
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete, :new, :create, :update_choice, :update_find]

  def privilege_check
    if session[:privilege] > 1
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW USER
  
  # Add new item form
  
  def new
    @user = User.new
    @users_array = User.select("email")
    
    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["user"].each {|key, value| value.strip!}
    params["user"]["email"].downcase!
    
    new_user = User.new(params["user"])
    new_user.password = params["user"]["password_hash"]

    if new_user.save
      flash[:message] = "New administrator successfully created:<br>
                  <ul><li><strong>Name:</strong> #{new_user.user_name}</li>
                  <li><strong>Email:</strong> #{new_user.email}</li>
                  <li><strong>ID:</strong> #{new_user.id}</li>
                  <li><strong>Privilege Level:</strong> #{new_user.privilege}</li></ul>"
      redirect_to "/admin/update_database"
  
    else 
      @error_messages = new_user.errors.to_a
      @user = User.new
      @users_array = User.select("email")
      render "new"
    end
  end
  
  ###########################################
  # UPDATE USER
  
  # Choose which item to update
  
  def update_find
    @user = User.new
    @users_array = User.select("id, email")
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/users/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @user = User.new
    @new_item = User.find_by_id(params["id"])
  end 
  
  # 'put' request that saves updates
  
  def update
    params["user"].each do |key, value| 
      value.strip!
      if value == ""
        params["user"].delete(key)
      end
    end
    
    params["user"]["email"].downcase!
    
    @prev_user_info = User.find_by_id(params["user"]["id"])
    existing_user = User.find_by_id(params["user"]["id"])
    
    if !params["user"]["password_hash"].blank?
      existing_user.password = params["user"]["password_hash"]
    end

    if existing_user.update_attributes(params["user"])
      @object = existing_user
      
      render "user_success"

    else
      @error_messages = existing_user.errors.to_a
      @user = User.new
      @new_item = User.find_by_id(params["id"])

      render "edit"
    end
  end   
  
 
end