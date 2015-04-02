# Module: FeministInstanceMethods
#
# Toolbox for use in the Daily Feminist Affirmation program; contains instance methods that could work for multiple classes.
#
# Public Methods:
# #search_table_by_value
# #save


module FeministInstanceMethods
  
  def get_keywords
    array = []
  
    self.keyword_items.each do |object|
      # object.respond_to?(:keyword) ? object.keyword : ""
      a = object.keyword.respond_to?(:keyword) ? object.keyword.keyword : "" 
      array.push a
    end
 
    
    return array
  end
  
  
  def keyword_check_for_no_method_error(method)
    self.respond_to?(:method) ? self.method : nil
  end



  def self.random(table)
    ids = connection.select_all("SELECT id FROM table")
    find(ids[rand(ids.length)]["id"].to_i) unless ids.blank?
  end
  
end