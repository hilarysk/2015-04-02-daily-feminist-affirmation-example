class TermsController < ApplicationController  
  layout "admin"
 
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete]

  def privilege_check
    if session[:privilege] == 3
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW TERM
  
  # Add new item form
  
  def new
    @term = Term.new
    @terms_array = Term.select("term")
    
    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["term"]["term"].downcase!
    params["term"]["term"].strip!
    params["term"]["definition"].strip!
    params["term"]["phonetic"].strip!
    params["term"]["user_id"] = session[:user_id]

    new_item = Term.new(params["term"])

    if new_item.valid?
      new_item.save
      @object = new_item   
      @success_message = "Your term was successfully added:"
        
      # Tags term with "term"
      item_keyword = Keyword.find_by_keyword("term")
      KeywordItem.create({"keyword_id"=>item_keyword.id, "item_type"=>"Term", "item_id"=>new_item.id})

      # Keyword message      
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Your new term was automatically tagged:
                      <ul><li><strong>\"term\"</strong></li></ul>
                      <br>Go <a href='/admin/tags/change?item_id=#{@object.id}&class=Term'>here</a> to add more keywords to describe this term.</p>"

      render "term_success", layout: "admin"
  
    else
      @error_messages = new_item.errors.to_a
      @term = Term.new
      @terms_array = Term.select("term")
      
      render "new"
    end
  end 
  
  ###########################################
  # UPDATE TERM
  
  # Choose which item to update
  
  def update_find
    @term = Term.new
    @terms_array = Term.select("id, term")
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/terms/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @term = Term.new
    @new_item = Term.find_by_id(params["id"])
  end 
  
  # 'put' request that saves updates
  
  def update
    params["term"]["user_id"] = session[:user_id]
    params["term"]["term"].strip!
    params["term"]["definition"].strip!
    params["term"]["phonetic"].strip!
    
    existing_item = Term.find_by_id(params["term"]["id"]) #object of existing excerpt
  
    if existing_item.update_attributes(params["term"])
      @object = existing_item
      @success_message = "The term was successfully updated:"
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Here are the current keywords: <br><strong><ul><li>#{existing_item.get_keywords.join('</li><li>')}</li></ul></strong><br>
                      <a href='/admin/tags/change?item_id=#{@object.id}&class=Term'>Add more keywords</a> to describe this excerpt, if you'd like.</p>"

      render "term_success"
  
    else 
      @error_messages = existing_item.errors.to_a
      render "edit"
  
    end
  end 
  
  ###########################################
  # DELETE TERM
  
  # Choose which item to delete
  
  def delete_find
    @term = Term.new
    @terms_array = Term.select("id, term")
    
    render "delete_find"
  end 
  
  # Sends choice to delete path
  
  def delete_choice
    redirect_to ("/admin/terms/#{params["id"]}/delete")
  end
  
  # Confirms that the user wants to delete the item
  
  def deleteconfirm
    @term = Term.new
    @new_item = Term.find_by_id(params["id"])
    
    render "delete_confirm"
  end
  
  # 'delete' request that actually deletes the chosen item
  
  def delete
    @object = Term.find(params["term"]["id"])
    @id = @object.id
    
    if @object.destroy
    
      @success_message = "The term was successfully deleted:"
      @add_keywords = ""
      
      # DELETE KEYWORD PAIRINGS FROM TABLE
      
      defunct_keywords = KeywordItem.where("item_type = ? AND item_id = ?", "Term", @id)
      
      if defunct_keywords != []
        defunct_keywords.each {|record| record.destroy}
      end

      render "term_success"
      
    else
      admins = (User.where("privilege = 1").collect {|admin| "#{admin.user_name}, #{admin.email}"}).join("</li><li>")
      @error_messages = "Something went wrong; please contact a Privilege 1 administrator:<br><br><ul><li>" + admins + "</li></ul>"
      
      render "delete_find"
    end
  end 
  
  
end