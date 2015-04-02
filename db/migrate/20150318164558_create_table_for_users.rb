class CreateTableForUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.text :user_name
      t.text :email
      t.text :password_hash
      t.integer :privilege
      t.datetime :created_at
    end
  end

end
