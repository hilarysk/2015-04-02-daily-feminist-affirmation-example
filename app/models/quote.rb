# Class: Quote
#
# Creates different products and gets information about them.
#
# Attributes:
# @quote     - String: Text of quote
# @id        - Integer: Quote ID, primary key for quotes table
# @person_id - Integer: ID from people table (foreign key)
# @errors    - Hash representing any errors when trying to create a new object

# attr_reader :id, :errors
# attr_accessor :person_id, :quote
#
# Public Methods:
# #insert
# #self.array_of_quote_records
# 
# Private Methods:
# #initialize

class Quote < ActiveRecord::Base
  include FeministInstanceMethods
  
  attr_accessible :quote, :person_id, :user_id, :created_at, :updated_at
  
  belongs_to :person
  belongs_to :user
  has_many :keyword_items, as: :item

  validates :quote, uniqueness: { case_sensitive: false }
  validates :quote, :person_id, :user_id, presence: true  
  
  def self.random
    ids = connection.select_all("SELECT id FROM quotes")
    find(ids[rand(ids.length)]["id"].to_i) unless ids.blank?
  end
  
end