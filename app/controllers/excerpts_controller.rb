class ExcerptsController < ApplicationController  
  layout "admin"
  
  # Sets instance variables for certain pages
  
  before_filter :set_variables, :only => [:new, :update_find, :edit, :delete_find]
  
  def set_variables
    @person_names_ids = Person.select("id, person")
    @excerpt_sources = Excerpt.uniq.pluck("source")
  end
  
  # MAKES SURE USER LEVEL ONE OR TWO PRIVILEGE BEFORE CAN DELETE

  before_filter :privilege_check, only: [:delete_find, :delete_choice, :deleteconfirm, :delete]

  def privilege_check
    if session[:privilege] == 3
      redirect_to ("/login?error=Looks like you might need to check your privilege; you don't seem to have permission to do that. :(.")
    end
  end
  
  ############################################
  # ADD NEW EXCERPT
  
  # Add new item form
  
  def new
    @excerpt = Excerpt.new
    @path = request.path_info
    
    if params["source"].nil? == false
      @text_array = Excerpt.where("source = ?", params["source"])
      @excerpt_choice = "sources_for_new_excerpt"
    end
    
    render "new"
  end
  
  # 'post' request that saves changes from new item form

  def create
    params["excerpt"]["excerpt"].strip!

    if params["excerpt"]["source"] == ""
      params["excerpt"]["source"] = params["source1"]
      params["excerpt"].delete("source1")
      params["excerpt"]["source"].strip!
    else
      params["excerpt"].delete("source1")
      params["excerpt"]["source"].strip!
      
    end  

    params["excerpt"]["user_id"] = session[:user_id]

    new_excerpt = Excerpt.new(params["excerpt"])

    if new_excerpt.valid?
      new_excerpt.save
      @object = new_excerpt   
      @person = Person.find_by_id(params["excerpt"]["person_id"]).person
      @success_message = "Your excerpt was successfully added:"
      
      ################### PULL OUT INTO SELF METHOD FOR EACH CLASS ###########################
  
      @source_keyword = Keyword.find_by_keyword(params["excerpt"]["source"])
      # If source for the new excerpt isn't already a keyword, it makes a  new one
      if @source_keyword == nil
        @source_keyword = Keyword.create({"keyword" => "#{params["excerpt"]["source"]}", "user_id"=>session["user_id"]})
      end
  
      # Tags excerpt with source
      KeywordItem.create({"keyword_id"=>@source_keyword.id, "item_type"=>"Excerpt", "item_id"=>new_excerpt.id})
      # Tags excerpt with person
      person_keyword = Keyword.find_by_keyword(new_excerpt.person.person)
      KeywordItem.create({"keyword_id"=>person_keyword.id, "item_type"=>"Excerpt", "item_id"=>new_excerpt.id})
      # Tags excerpt with "excerpt"
      excerpt_keyword = Keyword.find_by_keyword("excerpt")
      KeywordItem.create({"keyword_id"=>excerpt_keyword.id, "item_type"=>"Excerpt", "item_id"=>new_excerpt.id})
  
      ########################################################################################
 
      # Keyword message      
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Your new excerpt was automatically tagged:
                      <ul><li><strong>\"#{@source_keyword.keyword}\"</strong></li>
                      <li><strong>\"#{person_keyword.keyword}\"</strong></li>
                      <li><strong>\"excerpt\"</strong></li></ul>
                      <br>Go <a href='/admin/tags/change?item_id=#{@object.id}&class=Excerpt'>here</a> to add more keywords to describe this excerpt.</p>"

      render "excerpt_success", layout: "admin"
  
    else
      @error_messages = new_excerpt.errors.to_a
      
      @excerpt = Excerpt.new
      @path = request.path_info
    
      if params["source"].nil? == false
        @text_array = Excerpt.where("source = ?", params["source"])
        @excerpt_choice = "sources_for_new_excerpt"
      end
      
      render "new"
    end
  end 
  
  ############################################
  # UPDATE EXCERPT
  
  # Choose which item to update
  
  def update_find
    @excerpt = Excerpt.new
    @path = request.path_info

    if params["source"].nil? == false
      @text_array = Excerpt.where("source = ?", params["source"])
      @excerpt_choice = "sources_for_updelete_excerpt"
      @excerpt = params["source"]
      @form_action = "/admin/excerpts/update_choice"
      @action = "update"
    end
        
    render "update_find"
  end 
  
  # Sends choice to edit path
  
  def update_choice
    redirect_to ("/admin/excerpts/#{params["id"]}/edit")
  end
  
  # Form to edit item
  
  def edit
    @excerpt = Excerpt.new
    @new_ex = Excerpt.find_by_id(params["id"])
    
    @person_names_ids.each do |object|
      if object.person == @new_ex.person.person
        return @person_names_ids.unshift(object)
      end
    end
    
  end 
  
  # 'put' request that saves updates
  
  def update
    
    params["excerpt"]["user_id"] = session[:user_id]
    params["excerpt"]["excerpt"].strip!
    params["excerpt"]["source"].strip!
    existing_excerpt = Excerpt.find_by_id(params["excerpt"]["id"]) #object of existing excerpt
  
    if existing_excerpt.update_attributes(params["excerpt"])
      @object = existing_excerpt
      person1 = Person.find_by_id(existing_excerpt.person_id).person
      @success_message = "The excerpt was successfully updated:"
      @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Here are the current keywords: <br><strong><ul><li>#{existing_excerpt.get_keywords.join('</li><li>')}</li></ul></strong><br>
                      <a href='/admin/tags/change?item_id=#{@object.id}&class=Excerpt'>Add more keywords</a> to describe this excerpt, if you'd like.</p>"

      render "excerpt_success"
  
    else 
      @error_messages = existing_excerpt.errors.to_a
      @excerpt = Excerpt.new
      @new_ex = Excerpt.find_by_id(params["id"])
      
      render "edit"
    end
  end 
  
  ############################################
  # DELETE EXCERPT
  
  # Choose which item to delete
  
  def delete_find
    @excerpt = Excerpt.new
    @path = request.path_info

    if params["source"].nil? == false
      @text_array = Excerpt.where("source = ?", params["source"])
      @excerpt_choice = "sources_for_updelete_excerpt"
      @excerpt = params["source"]
      @form_action = "/admin/excerpts/delete_choice"
      @action = "delete"
    end
    
    render "delete_find"
  end 
  
  # Sends choice to delete path
  
  def delete_choice
    redirect_to ("/admin/excerpts/#{params["id"]}/delete")
  end
  
  # Confirms that the user wants to delete the item
  
  def deleteconfirm
    @excerpt = Excerpt.new
    @new_ex = Excerpt.find_by_id(params["id"])
    
    render "delete_confirm", layout: "admin"
  end
  
  # 'delete' request that actually deletes the chosen item
  
  def delete
    @object = Excerpt.find(params["excerpt"]["id"])
    person1 = @object.person.person
    @id = @object.id
    
    if @object.destroy
    
      @success_message = "The excerpt was successfully deleted:"
      @add_keywords = ""
      
      # DELETE KEYWORD PAIRINGS FROM TABLE
      
      defunct_keywords = KeywordItem.where("item_type = ? AND item_id = ?", "Excerpt", @id)
      
      if defunct_keywords != []
        defunct_keywords.each {|record| record.destroy}
      end

      render "excerpt_success", layout: "admin"
      
    else
      admins = (User.where("privilege = 1").collect {|admin| "#{admin.user_name}, #{admin.email}"}).join("<br>")
      @error_messages = "Something went wrong; please contact a Level One administrator:<br><br>" + admins
      
      render "delete_find", layout: "admin"
    end
  end 
  
end
    
  