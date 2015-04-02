# Class: Person
#
# Creates different people and gets information about them.
#
# Attributes:
# @person  - String: Name of person
# @id      - Integer: Person ID, primary key for people table
# @bio     - String: Person's biography
# @state   - String: State where person was born
# @country - String: Country where person was born
# @image   - String: Link to the person's image
# @caption - String: Caption for image
# @source  - String: Source for the biography
# @errors  - Instance variable representing any errors when trying to create a new object
#
# attr_reader :id, :errors
# attr_accessor :country, :bio, :state, :person, :caption, :image, :source
#
# Public Methods:
# #insert
# #self.array_of_person_records
# 
# Private Methods:
# #initialize

class Person < ActiveRecord::Base
  include FeministInstanceMethods
  
  attr_accessible :person, :bio, :state, :country, :image, :caption, :source, :user_id, :created_at, :updated_at 

  has_many :excerpts
  has_many :quotes
  belongs_to :user
  has_many :keyword_items, as: :item
  
  validates :person, :bio, :image, uniqueness: { case_sensitive: false }
  validates :person, :bio, :country, :image, :caption, :source, :user_id, presence: true  
  
  def self.random
    ids = connection.select_all("SELECT id FROM people")
    find(ids[rand(ids.length)]["id"].to_i) unless ids.blank?
  end
end