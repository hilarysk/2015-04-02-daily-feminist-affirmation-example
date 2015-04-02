class CreateTableForQuote < ActiveRecord::Migration
  def change
    create_table :quotes do |t|
    t.text :quote
    t.integer :person_id
    t.integer :user_id
    t.datetime :created_at
    t.datetime :updated_at
    end
  end

end
