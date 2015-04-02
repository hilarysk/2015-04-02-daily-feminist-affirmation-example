class QuotesController < ApplicationController  
  layout "admin"
  
  # Sets instance variables for certain pages
  
  before_filter :set_variables, :only => [:new, :update_find, :edit, :delete_find]
  
  def set_variables
    @person_names_ids = Person.select("id, person")
  end
  
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete]

  def privilege_check
    if session[:privilege] == 3
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW QUOTE
  
  # Add new item form
  
  def new
    @quote = Quote.new
    @path = request.path_info
    
    if params["person_id"].nil? == false
      @quote_array = Quote.where("person_id = ?", params["person_id"])
      @quote_choice = "persons_for_new_quote"
      @person = Person.find(params["person_id"]).person
    end
    
    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["quote"]["quote"].strip!
    params["quote"]["user_id"] = session[:user_id]

    new_item = Quote.new(params["quote"])

    if new_item.valid?
      new_item.save
      @object = new_item   
      @person = Person.find_by_id(params["quote"]["person_id"]).person
      @success_message = "Your quote was successfully added:"
      
      ################### PULL OUT INTO SELF METHOD FOR EACH CLASS ###########################
  
      # Tags quote with person
      person_keyword = Keyword.find_by_keyword(new_item.person.person)
      KeywordItem.create({"keyword_id"=>person_keyword.id, "item_type"=>"Quote", "item_id"=>new_item.id})
      # Tags quote with "quote"
      quote_keyword = Keyword.find_by_keyword("quote")
      KeywordItem.create({"keyword_id"=>quote_keyword.id, "item_type"=>"Quote", "item_id"=>new_item.id})
  
      ########################################################################################
 
      # Keyword message      
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Your new quote was automatically tagged:
                      <ul><li><strong>\"#{person_keyword.keyword}\"</strong></li>
                      <li><strong>\"quote\"</strong></li></ul>
                      <br>Go <a href='/admin/tags/change?item_id=#{@object.id}&class=Quote'>here</a> to add more keywords to describe this excerpt.</p>"

      render "quote_success"
  
    else
      @error_messages = new_item.errors.to_a
      @quote = Quote.new
      @path = request.path_info
    
      if params["person_id"].nil? == false
        @quote_array = Quote.where("person_id = ?", params["person_id"])
        @quote_choice = "persons_for_new_quote"
        @person = Person.find(params["person_id"]).person
      end
    
      render "new"
    end
  end 
  
  ############################################
  # UPDATE QUOTE
  
  # Choose which item to update
  
  def update_find
    @quote = Quote.new
    @path = request.path_info

    if params["person_id"].nil? == false
      @quote_array = Quote.where("person_id = ?", params["person_id"])
      @quote_choice = "persons_for_updelete_quote"
      @person = Person.find(params["person_id"]).person
      @action = "update"
      @form_action = "/admin/quotes/update_choice"
    end
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/quotes/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @quote = Quote.new
    @new_item = Quote.find_by_id(params["id"])
    
    @person_names_ids.each do |object|
      if object.person == @new_item.person.person
        return @person_names_ids.unshift(object)
      end
    end
    
  end 
  
  # 'put' request that saves updates
  
  def update
    
    params["quote"]["user_id"] = session[:user_id]
    params["quote"]["quote"].strip!
    existing_quote = Quote.find_by_id(params["quote"]["id"]) #object of existing excerpt
    binding.pry
  
    if existing_quote.update_attributes(params["quote"])
      @object = existing_quote
      person1 = Person.find_by_id(existing_quote.person_id).person
      @success_message = "The quote was successfully updated:"
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Here are the current keywords: <br><strong><ul><li>#{existing_quote.get_keywords.join('</li><li>')}</li></ul></strong><br>
                      <a href='/admin/tags/change?item_id=#{@object.id}&class=Quote'>Add more keywords</a> to describe this quote, if you'd like.</p>"

      render "quote_success"
  
    else 
      @error_messages = existing_quote.errors.to_a
      @quote = Quote.new
      @new_item = Quote.find_by_id(params["id"])
      
      render "edit"
    end
  end 
  
  ############################################
  # DELETE QUOTE
  
  # Choose which item to delete
  
  def delete_find
    @quote = Quote.new
    @path = request.path_info

    if params["person_id"].nil? == false
      @quote_array = Quote.where("person_id = ?", params["person_id"])
      @quote_choice = "persons_for_updelete_quote"
      @person = Person.find(params["person_id"]).person
      @action = "update"
      @form_action = "/admin/quotes/delete_choice"
    end
    
    render "delete_find"
  end 
  
  # Sends choice to delete path
  
  def delete_choice
    redirect_to ("/admin/quotes/#{params["id"]}/delete")
  end
  
  # Confirms that the user wants to delete the item
  
  def deleteconfirm
    @quote = Quote.new
    @new_item = Quote.find_by_id(params["id"])
    
    render "delete_confirm"
  end
  
  # 'delete' request that actually deletes the chosen item
  
  def delete
    @object = Quote.find(params["quote"]["id"])
    person1 = @object.person.person
    @id = @object.id
    
    if @object.destroy
    
      @success_message = "The quote was successfully deleted:"
      @add_keywords = ""
      
      # DELETE KEYWORD PAIRINGS FROM TABLE
      
      defunct_keywords = KeywordItem.where("item_type = ? AND item_id = ?", "Quote", @id)
      
      if defunct_keywords != []
        defunct_keywords.each {|record| record.destroy}
      end

      render "quote_success"
      
    else
      admins = (User.where("privilege = 1").collect {|admin| "#{admin.user_name}, #{admin.email}"}).join("<br>")
      @error_messages = "Something went wrong; please contact a Level One administrator:<br><br>" + admins
      
      render "delete_find"
    end
  end 
  
end