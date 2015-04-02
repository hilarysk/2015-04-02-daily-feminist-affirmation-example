class PeopleController < ApplicationController  
  layout "admin"
    
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete]

  def privilege_check
    if session[:privilege] == 3
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW PERSON
  
  # Add new item form
  
  def new
    @person = Person.new
    @people_array = Person.select("person")
    
    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["person"].each {|key, value| value.strip!}
    params["person"]["user_id"] = session[:user_id]

    new_item = Person.new(params["person"])

    if new_item.valid?
      new_item.save
      @object = new_item   
      @success_message = "Your person was successfully added:"
        
      # Tags person with "person"
      item_keyword = Keyword.find_by_keyword("person")
      KeywordItem.create({"keyword_id"=>item_keyword.id, "item_type"=>"Person", "item_id"=>new_item.id})
      
      @person_keyword = Keyword.find_by_keyword(params["person"]["person"])
      # If the person's name isn't already a keyword, it makes a new one
      if @person_keyword == nil
        @person_keyword = Keyword.create({"keyword" => "#{params["person"]["person"]}"})
      end
  
      # Tags person with their name
      KeywordItem.create({"keyword_id"=>@person_keyword.id, "item_type"=>"Person", "item_id"=>new_item.id})
      
      @country_keyword = Keyword.find_by_keyword(params["person"]["country"])
      # If the person's country isn't already a keyword, it makes a new one
      if @country_keyword == nil
        @country_keyword = Keyword.create({"keyword" => "#{params["person"]["country"]}", "user_id"=>session["user_id"]})
      end
  
      # Tags person with their country
      KeywordItem.create({"keyword_id"=>@country_keyword.id, "item_type"=>"Person", "item_id"=>new_item.id})
      
      if params["person"]["state"] != nil && params["person"]["state"] != ""
        @state_keyword = Keyword.find_by_keyword(params["person"]["state"])
        # If the person's state isn't already a keyword, it makes a new one
        if @state_keyword == nil
          @state_keyword = Keyword.create({"keyword" => "#{params["person"]["state"]}", "user_id"=>session["user_id"]})
        end
        
        # Tags person with their state
        KeywordItem.create({"keyword_id"=>@state_keyword.id, "item_type"=>"Person", "item_id"=>new_item.id})
        
      else
        @state_keyword = nil
      end
      
      # Keyword message      
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Your new term was automatically tagged:
                      <ul><li><strong>\"person\"</strong></li>
                      <li><strong>\"#{@person_keyword}\"</strong></li>
                      <% if @state_keyword != nil %>
                        <li><strong>\"#{@state_keyword}\"</strong></li>
                      <% end %>
                      <li><strong>\"#{@country_keyword}\"</strong></li></ul>
                      <br>Go <a href='/admin/tags/change?item_id=#{@object.id}&class=Person'>here</a> to add more keywords to describe this term.</p>"

      render "person_success"
  
    else
      @error_messages = new_item.errors.to_a
      @person = Person.new
      @people_array = Person.select("person")
        
      render "new"
    end
  end 
  
  ###########################################
  # UPDATE PERSON
  
  # Choose which item to update
  
  def update_find
    @person = Person.new
    @people_array = Person.select("id, person")
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/people/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @person = Person.new
    @new_item = Person.find_by_id(params["id"])
  end 
  
  # 'put' request that saves updates
  
  def update
    params["person"].each {|key, value| value.strip!}
    params["person"]["user_id"] = session[:user_id]

    
    existing_item = Person.find_by_id(params["id"]) #object of existing person
  
    if existing_item.update_attributes(params["person"])
      @object = existing_item
      @success_message = "The person was successfully updated:"
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Here are the current keywords: <br><strong><ul><li>#{existing_item.get_keywords.join('</li><li>')}</li></ul></strong><br>
                      <a href='/admin/tags/change?item_id=#{@object.id}&class=Person'>Add more keywords</a> to describe this person, if you'd like.</p>"

      render "person_success"
  
    else 
      @error_messages = existing_item.errors.to_a
      @person = Person.new
      @new_item = Person.find_by_id(params["id"])
      
      render "edit"
    end
  end 
  
  ###########################################
  # DELETE PERSON
  
  # Choose which item to delete
  
  def delete_find
    @person = Person.new
    @people_array = Person.select("id, person")
    
    render "delete_find"
  end 
  
  # Sends choice to delete path
  
  def delete_choice
    redirect_to ("/admin/people/#{params["id"]}/delete")
  end
  
  # Confirms that the user wants to delete the item
  
  def deleteconfirm
    @person = Person.new
    @new_item = Person.find_by_id(params["id"])
    
    render "delete_confirm"
  end
  
  # 'delete' request that actually deletes the chosen item
  
  def delete
    @object = Person.find(params["person"]["id"])
    @id = @object.id
    
    if @object.destroy
    
      @success_message = "The person was successfully deleted:"
      @add_keywords = ""
      
      # DELETE KEYWORD PAIRINGS FROM TABLE
      
      defunct_keywords = KeywordItem.where("item_type = ? AND item_id = ?", "Person", @id)
      
      if defunct_keywords != []
        defunct_keywords.each {|record| record.destroy}
      end

      render "person_success"
      
    else
      admins = (User.where("privilege = 1").collect {|admin| "#{admin.user_name}, #{admin.email}"}).join("<br>")
      @error_messages = "Something went wrong; please contact a Level One administrator:<br><br>" + admins
      
      render "delete_find"
    end
  end 
  
  
end