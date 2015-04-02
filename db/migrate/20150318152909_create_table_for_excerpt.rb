class CreateTableForExcerpt < ActiveRecord::Migration
 
  def change
    create_table :excerpts do |t|
      t.text :excerpt
      t.text :source
      t.integer :person_id
      t.integer :user_id
      t.datetime :created_at
      t.datetime :updated_at
    end
  end

end
