class CreateTableForPeople < ActiveRecord::Migration
  def change
    create_table :people do |t|
      t.text :person
      t.text :bio
      t.text :state
      t.text :country
      t.text :image
      t.text :caption
      t.text :source
      t.integer :user_id
      t.datetime :created_at
      t.datetime :updated_at
    end
  end
end
