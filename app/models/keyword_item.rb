# Class: KeywordItem
#
# Creates keyword-item pairs
#
# Attributes:
# @keyword_id    - Integer: ID for the keyword (primary key from the keywords table)
# @item_id       - Integer: ID for the item (primary key ID from corresponding table)
# @item_type     - String: Table where the item resides
#
#
# attr_accessor :item_id, :keyword_id, :item_table_id
#
# Public Methods:
# #insert
# #self.get_array_keywords_for_item
# #self.get_array_items_for_keyword
# 
# Private Methods:
# #initialize
# #grab_table_item_id_for_specific_keyword
# #grab_items_given_id_table_keyword
# #get_person_name_for_keyword_items

class KeywordItem < ActiveRecord::Base
  include FeministInstanceMethods
  
  attr_accessible :keyword_id, :item_id, :item_type
  
  belongs_to :keyword
  belongs_to :user_id
  belongs_to :item, polymorphic: true #builds in item_id and item_type
    
end