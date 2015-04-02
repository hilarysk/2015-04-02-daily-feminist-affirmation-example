class KeywordsController < ApplicationController  
  layout "admin"
    
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete]

  def privilege_check
    if session[:privilege] == 3
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW KEYWORD
  
  # Add new item form
  
  def new
    @keyword = Keyword.new
    @keywords_array = Keyword.select("keyword")

    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["keyword"]["keyword"].downcase!
    params["keyword"]["keyword"].strip!
    params["keyword"]["user_id"] = session[:user_id]

    new_item = Keyword.new(params["keyword"])

    if new_item.valid?
      new_item.save
      @object = new_item   
      @success_message = "Your keyword was successfully added:"
        
      # Keyword message      
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3>"

      render "keyword_success"
  
    else
      @error_messages = new_item.errors.to_a
      @keyword = Keyword.new
      @keywords_array = Keyword.select("keyword")
      
      render "new"
    end
  end 
  
  ###########################################
  # UPDATE KEYWORD
  
  # Choose which item to update
  
  def update_find
    @keyword = Keyword.new
    @keywords_array = Keyword.select("id, keyword")
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/keywords/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @keyword = Keyword.new
    @new_item = Keyword.find_by_id(params["id"])
  end 
  
  # 'put' request that saves updates
  
  def update
    params["keyword"]["user_id"] = session[:user_id]
    params["keyword"]["keyword"].downcase!
    params["keyword"]["keyword"].strip!
    binding.pry
    existing_item = Keyword.find_by_id(params["id"]) #object of existing excerpt
  
    if existing_item.update_attributes(params["keyword"])
      @object = existing_item
      @success_message = "The keyword was successfully updated:"
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>"

      render "keyword_success"
  
    else 
      @error_messages = existing_item.errors.to_a
      @keyword = Keyword.new
      @new_item = Keyword.find_by_id(params["id"])
      
      render "edit"
    end
  end 
  
  ###########################################
  # DELETE KEYWORD
  
  # Choose which item to delete
  
  def delete_find
    @keyword = Keyword.new
    @keywords_array = Keyword.select("id, keyword")
    
    render "delete_find"
  end 
  
  # Sends choice to delete path
  
  def delete_choice
    redirect_to ("/admin/keywords/#{params["id"]}/delete")
  end
  
  # Confirms that the user wants to delete the item
  
  def deleteconfirm
    @keyword = Keyword.new
    @new_item = Keyword.find_by_id(params["id"])
    
    render "delete_confirm"
  end
  
  # 'delete' request that actually deletes the chosen item
  
  def delete
    @object = Keyword.find(params["keyword"]["id"])
    @id = @object.id
    
    if @object.destroy
    
      @success_message = "The keyword was successfully deleted:"
      
      # DELETE KEYWORD PAIRINGS FROM TABLE
      
      defunct_keywords = KeywordItem.where("keyword_id = ?", @id)
      
      if defunct_keywords != []
        defunct_keywords.each {|record| record.destroy}
      end

      render "keyword_success"
      
    else
      admins = (User.where("privilege = 1").collect {|admin| "#{admin.user_name}, #{admin.email}"}).join("<br>")
      @error_messages = "Something went wrong; please contact a Level One administrator:<br><br>" + admins
      
      render "delete_find"
    end
  end 
  
  
end