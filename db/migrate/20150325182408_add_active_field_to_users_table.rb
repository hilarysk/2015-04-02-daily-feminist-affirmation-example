class AddActiveFieldToUsersTable < ActiveRecord::Migration
  def change
    add_column :users, :status, :string, default: "active"
  end
end
