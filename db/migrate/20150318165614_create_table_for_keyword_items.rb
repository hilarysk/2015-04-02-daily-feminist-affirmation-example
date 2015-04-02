class CreateTableForKeywordItems < ActiveRecord::Migration
  def change
    create_table :keyword_items do |t|
     t.integer :keyword_id
     t.integer :item_id
     t.text :item_type
    end
  end
end
