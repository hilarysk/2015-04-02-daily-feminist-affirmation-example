# Class: Term
#
# Creates different products and gets information about them.
#
# Attributes:
# @id         - Integer: Instance variable representing the term ID (primary key)
# @definition - String: Variable representing the term's definition
# @term       - String: Variable representing the term 
# @phonetic   - String: The phoentic spelling of the term
#
#
# Public Methods:
# #insert
# #self.array_of_term_records
# 
# Private Methods:
# #initialize

class Term < ActiveRecord::Base
  include FeministInstanceMethods
  
  attr_accessible :term, :definition, :phonetic, :user_id, :created_at, :updated_at
  
  belongs_to :user
  has_many :keyword_items, as: :item  
  
  validates :term, :definition, :phonetic, uniqueness: { case_sensitive: false }
  validates :term, :definition, :phonetic, :user_id, presence: true  
  
  def self.random
    ids = connection.select_all("SELECT id FROM terms")
    find(ids[rand(ids.length)]["id"].to_i) unless ids.blank?
  end
      
end