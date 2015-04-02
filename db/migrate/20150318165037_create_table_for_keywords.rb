class CreateTableForKeywords < ActiveRecord::Migration
  def change
    create_table :keywords do |t|
      t.text :keyword
      t.integer :user_id
      t.datetime :created_at
      t.datetime :updated_at
    end
  end

end
