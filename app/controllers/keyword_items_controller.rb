class KeywordItemsController < ApplicationController  
  layout "admin"
  
  # Loads page where user can click or unclick specific keywords for a specific item
  
  def choose
    @excerpt = Excerpt.new
    @path = request.path_info
    
    if params["type"].nil? == false
      @item_choice = "item"
      @item_class = params["type"]
    end
    
    if params["item_id"].nil? == false
      @item_tags = "tags"
      @item = params["class"].constantize.find(params["item_id"])
      @existing_keywords = @item.get_keywords
      
    end
    
    render "choose"
  end
  
  # Can be refactored; compares existing keywords with new keywords and adds or deletes items, as necessary.
  
  def change
    @object = (params["table"].constantize).find(params["id"])
    existing_keywords = @object.keyword_items
    existing_keywords_ids = []
    new_keywords = params["keyword"]
    existing_keywords.each {|keyword_object| existing_keywords_ids.push keyword_object.keyword_id }

    existing_keywords_ids.each do |id|
      if new_keywords.include?(id.to_s) == false
        a = KeywordItem.where("keyword_id = ? and item_type = ? and item_id = ?", id, params['table'].capitalize, @object.id)
        a[0].destroy
      end
    end
    
    new_keywords_show = []
    
    new_keywords.each do |new_id|
      if existing_keywords_ids.include?(new_id.to_i) == false
        KeywordItem.create({"keyword_id"=>new_id.to_i, "item_id"=>@object.id, "item_type"=>"#{params['table'].capitalize}"})
      end
      new_keywords_show.push (Keyword.find(new_id).keyword)
    end
    
    @success_message = "The keywords were successfully updated:"
    @add_keywords = "<hr></hr><h3><em>Thank you!</em></h3><p>Here are the new keywords: <br><strong><ul><li>#{new_keywords_show.join('</li><li>')}</li></ul></strong><br>"

    render "tag_success"
  end
  
end