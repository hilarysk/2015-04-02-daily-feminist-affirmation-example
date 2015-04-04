class ApplicationController < ActionController::Base
  protect_from_forgery
  before_filter :session_check, except: [:logout, :user_verify]
  
  
  def session_check
    if session[:user_id] == nil
      flash[:error] = "Oops! Looks like you need to login first."
      return redirect_to ("/login")
   elsif session[:status] == "inactive"
      return redirect_to ("/admin/inactive")
    end
  end
  
  ################################################
  
  # CHECKS TO MAKE SURE USER IS IN SYSTEM; IF NOT, RETURNS THEM TO LOGIN PAGE WITH ERROR MESSAGE
  
  def user_verify
    user = User.find_by_email(params["email"].downcase) 

    if BCrypt::Password.new(user.password) == params["password"].to_s
      session[:user_id] = user.id
      session[:email] = user.email
      session[:privilege] = user.privilege
      session[:user_name] = user.user_name
      session[:status] = user.status
      
      if session[:status] == "inactive"
        return redirect_to ("/admin/inactive")
      else
        return redirect_to ("/admin/update_database")
      end
    
    else 
      flash["error"] = "We couldn't find you in the system; please try again."
      redirect_to ("/login")    
    end

  end
  
  # LOGOUT ROUTE ADDS LOGOUT MESSAGE LOADS LOGIN
  
  def logout
    @logout_message = "You have successfully logged out. Thanks for contributing!"
    render "/admin/login", layout: "public"
  end
  
  
  
end
