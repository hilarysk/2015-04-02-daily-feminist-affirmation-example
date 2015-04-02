class AdminController < ApplicationController
  # MAKES SURE USER IS LOGGED-IN BEFORE ADMIN PAGE WILL LOAD
  skip_before_filter :session_check, only: [:login, :login_forgot, :logout, :inactive]
  
  
  # IF USER IS ALREADY LOGGED IN, GOING TO LOGIN PAGE SENDS THEM TO UPDATE DATABASE
  
  before_filter :already_logged_in, :only => [:login]
  
  def already_logged_in
    if session[:user_id] != nil
      redirect_to("/admin/update_database")
    end
  end


  # BEFORE LOGOUT, RESETS SESSION  
  
  before_filter :clear_session, :only => :logout
  
  def clear_session
    session[:user_id] = nil
    session[:email] = nil
    session[:privilege] = nil
    session[:user_name] = nil
    session[:message] = nil
    session[:status] = nil
  end
  
  # AFTER LOADS DATABASE PAGE FIRST TIME, CLEARS SESSION MESSAGE
  
  after_filter :clear_session_message, :only => :update_database
  
  def clear_session_message
    session[:message] = nil
  end 
  
  ##################################################
  
  # PAGE FOR FUNCTIONALITIES THAT AREN'T, YOU KNOW, FUNCTIONAL YET
  
  def coming_soon
    render layout: "admin"
  end
  
  # WHERE USER LOGS IN
  
  def login
    @fail_message = params["error"]
    render layout: "public"
  end
  
  # NOTE: user verification takes place in application so that session applies to all controllers? Probably unnecessary ....
  
  # LOADS PAGE WITH ADMINISTRATIVE ACTIONS
  
  def update_database
    @error = params["error"]
    @message = session[:message]
  end
    
  # SHOWS EVERYTHING ADDED BY A SPECIFIC CONTRIBUTOR, IN DESCENDING ORDER
  
  def contrib
    @all_admins = User.all
    @path = request.path_info

    if params["id"].nil? == false
      @user = User.find_by_id(params["id"])
      @items = @user.items_array_sorted_descending
      @specific_contrib = "/admin/contrib_partial"
    end
  end    


end


