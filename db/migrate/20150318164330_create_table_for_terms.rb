class CreateTableForTerms < ActiveRecord::Migration
  def change
    create_table :terms do |t|
      t.text :term
      t.text :definition
      t.text :phonetic
      t.integer :user_id
      t.datetime :created_at
      t.datetime :updated_at
    end
  end
end
