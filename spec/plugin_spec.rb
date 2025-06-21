# frozen_string_literal: true

require "rails_helper"

describe OAuth2BasicAuthenticator do
  describe "after_authenticate" do
    before { SiteSetting.oauth2_user_json_url = "https://provider.com/user" }

    let(:user) { Fabricate(:user) }
    let(:authenticator) { OAuth2BasicAuthenticator.new }

    let(:auth) do
      OmniAuth::AuthHash.new(
        "provider" => "oauth2_basic",
        "credentials" => {
          token: "token",
        },
        "uid" => "123456789",
        "info" => {
          id: "id",
        },
        "extra" => {
        },
      )
    end

    before(:each) { SiteSetting.oauth2_email_verified = true }

    it "finds user by email" do
      authenticator.expects(:fetch_user_details).returns(email: user.email)
      result = authenticator.after_authenticate(auth)
      expect(result.user).to eq(user)
    end

    it "validates user email if provider has verified" do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: true)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)
    end

    it "doesn't validate user email if provider hasn't verified" do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: nil)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(false)
    end

    it "doesn't affect the site setting" do
      SiteSetting.oauth2_email_verified = true
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: false)
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)
    end

    it "handles true/false strings from identity provider" do
      SiteSetting.oauth2_email_verified = false
      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: "true")
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(true)

      authenticator.stubs(:fetch_user_details).returns(email: user.email, email_verified: "false")
      result = authenticator.after_authenticate(auth)
      expect(result.email_valid).to eq(false)
    end

    describe "fetch_user_details" do
      before(:each) do
        SiteSetting.oauth2_fetch_user_details = true
        SiteSetting.oauth2_user_json_url = "https://provider.com/user"
        SiteSetting.oauth2_user_json_url_method = "GET"
        SiteSetting.oauth2_json_email_path = "account.email"
      end

      let(:success_response) do
        { status: 200, body: '{"account":{"email":"newemail@example.com"}}' }
      end

      let(:fail_response) { { status: 403 } }

      it "works" do
        stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(success_response)
        result = authenticator.after_authenticate(auth)
        expect(result.email).to eq("newemail@example.com")

        SiteSetting.oauth2_user_json_url_method = "POST"
        stub_request(:post, SiteSetting.oauth2_user_json_url).to_return(success_response)
        result = authenticator.after_authenticate(auth)
        expect(result.email).to eq("newemail@example.com")
      end

      it "returns an standardised result if the http request fails" do
        stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(fail_response)
        result = authenticator.after_authenticate(auth)
        expect(result.failed).to eq(true)

        SiteSetting.oauth2_user_json_url_method = "POST"
        stub_request(:post, SiteSetting.oauth2_user_json_url).to_return(fail_response)
        result = authenticator.after_authenticate(auth)
        expect(result.failed).to eq(true)
      end

      describe "fetch custom attributes" do
        after { DiscoursePluginRegistry.reset_register!(:oauth2_basic_additional_json_paths) }

        let(:response) do
          {
            status: 200,
            body: '{"account":{"email":"newemail@example.com","custom_attr":"received"}}',
          }
        end

        it "stores custom attributes in the user associated account" do
          custom_path = "account.custom_attr"
          DiscoursePluginRegistry.register_oauth2_basic_additional_json_path(
            custom_path,
            Plugin::Instance.new,
          )
          stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(response)

          result = authenticator.after_authenticate(auth)
          associated_account = UserAssociatedAccount.last

          expect(associated_account.extra[custom_path]).to eq("received")
        end
      end

      describe "required attributes" do
        after { DiscoursePluginRegistry.reset_register!(:oauth2_basic_required_json_paths) }

        it "'authenticates' successfully if required json path is fulfilled" do
          DiscoursePluginRegistry.register_oauth2_basic_additional_json_path(
            "account.is_legit",
            Plugin::Instance.new,
          )
          DiscoursePluginRegistry.register_oauth2_basic_required_json_path(
            { path: "extra:account.is_legit", required_value: true },
            Plugin::Instance.new,
          )

          response = {
            status: 200,
            body: '{"account":{"email":"newemail@example.com","is_legit":true}}',
          }
          stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(response)

          result = authenticator.after_authenticate(auth)
          expect(result.failed).to eq(false)
        end

        it "fails 'authentication' if required json path is unfulfilled" do
          DiscoursePluginRegistry.register_oauth2_basic_additional_json_path(
            "account.is_legit",
            Plugin::Instance.new,
          )
          DiscoursePluginRegistry.register_oauth2_basic_required_json_path(
            {
              path: "extra:account.is_legit",
              required_value: true,
              error_message: "You're not legit",
            },
            Plugin::Instance.new,
          )
          response = {
            status: 200,
            body: '{"account":{"email":"newemail@example.com","is_legit":false}}',
          }
          stub_request(:get, SiteSetting.oauth2_user_json_url).to_return(response)

          result = authenticator.after_authenticate(auth)
          expect(result.failed).to eq(true)
          expect(result.failed_reason).to eq("You're not legit")
        end
      end
    end

    describe "avatar downloading" do
      before do
        Jobs.run_later!
        SiteSetting.oauth2_fetch_user_details = true
        SiteSetting.oauth2_email_verified = true
      end

      let(:job_klass) { Jobs::DownloadAvatarFromUrl }

      before do
        png =
          Base64.decode64(
            "R0lGODlhAQABALMAAAAAAIAAAACAAICAAAAAgIAAgACAgMDAwICAgP8AAAD/AP//AAAA//8A/wD//wBiZCH5BAEAAA8ALAAAAAABAAEAAAQC8EUAOw==",
          )
        stub_request(:get, "http://avatar.example.com/avatar.png").to_return(
          body: png,
          headers: {
            "Content-Type" => "image/png",
          },
        )
      end

      it "enqueues a download_avatar_from_url job for existing user" do
        authenticator.expects(:fetch_user_details).returns(
          email: user.email,
          avatar: "http://avatar.example.com/avatar.png",
        )
        expect { authenticator.after_authenticate(auth) }.to change { job_klass.jobs.count }.by(1)

        job_args = job_klass.jobs.last["args"].first

        expect(job_args["url"]).to eq("http://avatar.example.com/avatar.png")
        expect(job_args["user_id"]).to eq(user.id)
        expect(job_args["override_gravatar"]).to eq(false)
      end

      it "enqueues a download_avatar_from_url job for new user" do
        authenticator.expects(:fetch_user_details).returns(
          email: "unknown@user.com",
          avatar: "http://avatar.example.com/avatar.png",
        )

        auth_result = nil
        expect { auth_result = authenticator.after_authenticate(auth) }.not_to change {
          job_klass.jobs.count
        }

        expect { authenticator.after_create_account(user, auth_result) }.to change {
          job_klass.jobs.count
        }.by(1)

        job_args = job_klass.jobs.last["args"].first

        expect(job_args["url"]).to eq("http://avatar.example.com/avatar.png")
        expect(job_args["user_id"]).to eq(user.id)
        expect(job_args["override_gravatar"]).to eq(false)
      end
    end
  end

  it "can walk json" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"user":{"id":1234,"email":{"address":"test@example.com"}}}'
    SiteSetting.oauth2_json_email_path = "user.email.address"
    result = authenticator.json_walk({}, JSON.parse(json_string), :email)

    expect(result).to eq "test@example.com"
  end

  it "allows keys containing dots, if wrapped in quotes" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"www.example.com/uid": "myuid"}'
    SiteSetting.oauth2_json_user_id_path = '"www.example.com/uid"'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "myuid"
  end

  it "allows keys containing dots, if escaped" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"www.example.com/uid": "myuid"}'
    SiteSetting.oauth2_json_user_id_path = 'www\.example\.com/uid'
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "myuid"
  end

  it "allows keys containing literal backslashes, if escaped" do
    authenticator = OAuth2BasicAuthenticator.new
    # This 'single quoted heredoc' syntax means we don't have to escape backslashes in Ruby
    # What you see is exactly what the user would enter in the site settings
    json_string = <<~'_'.chomp
      {"www.example.com/uid\\": "myuid"}
    _
    SiteSetting.oauth2_json_user_id_path = <<~'_'.chomp
      www\.example\.com/uid\\
    _
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)
    expect(result).to eq "myuid"
  end

  it "can walk json that contains an array" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string =
      '{"email":"test@example.com","identities":[{"user_id":"123456789","provider":"auth0","isSocial":false}]}'
    SiteSetting.oauth2_json_user_id_path = "identities.[].user_id"
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq "123456789"
  end

  it "can walk json and handle an empty array" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"email":"test@example.com","identities":[]}'
    SiteSetting.oauth2_json_user_id_path = "identities.[].user_id"
    result = authenticator.json_walk({}, JSON.parse(json_string), :user_id)

    expect(result).to eq nil
  end

  it "can walk json and find values by index in an array" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"emails":[{"value":"test@example.com"},{"value":"test2@example.com"}]}'
    SiteSetting.oauth2_json_email_path = "emails[1].value"
    result = authenticator.json_walk({}, JSON.parse(json_string), :email)

    expect(result).to eq "test2@example.com"
  end

  it "can walk json and download avatar" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"user":{"avatar":"http://example.com/1.png"}}'
    SiteSetting.oauth2_json_avatar_path = "user.avatar"
    result = authenticator.json_walk({}, JSON.parse(json_string), :avatar)

    expect(result).to eq "http://example.com/1.png"
  end

  it "can walk json and appropriately assign a `false`" do
    authenticator = OAuth2BasicAuthenticator.new
    json_string = '{"user":{"id":1234, "data": {"address":"test@example.com", "is_cat": false}}}'
    SiteSetting.oauth2_json_email_verified_path = "user.data.is_cat"
    result =
      authenticator.json_walk(
        {},
        JSON.parse(json_string),
        "extra:user.data.is_cat",
        custom_path: "user.data.is_cat",
      )

    expect(result).to eq false
  end

  describe "token_callback" do
    let(:user) { Fabricate(:user) }
    let(:strategy) { OmniAuth::Strategies::Oauth2Basic.new({}) }
    let(:authenticator) { OAuth2BasicAuthenticator.new }

    let(:auth) do
      OmniAuth::AuthHash.new(
        "provider" => "oauth2_basic",
        "credentials" => {
          "token" => "token",
        },
        "uid" => "e028b1b918853eca7fba208a9d7e9d29a6e93c57",
        "info" => {
          "name" => "Sammy the Shark",
          "email" => "sammy@digitalocean.com",
        },
        "extra" => {
        },
      )
    end

    let(:access_token) do
      {
        "params" => {
          "info" => {
            "name" => "Sammy the Shark",
            "email" => "sammy@digitalocean.com",
            "uuid" => "e028b1b918853eca7fba208a9d7e9d29a6e93c57",
          },
        },
      }
    end

    before(:each) do
      SiteSetting.oauth2_callback_user_id_path = "params.info.uuid"
      SiteSetting.oauth2_callback_user_info_paths = "name:params.info.name|email:params.info.email"
    end

    it "can retrieve user id from access token callback" do
      strategy.stubs(:access_token).returns(access_token)
      expect(strategy.uid).to eq "e028b1b918853eca7fba208a9d7e9d29a6e93c57"
    end

    it "can retrieve user properties from access token callback" do
      strategy.stubs(:access_token).returns(access_token)
      expect(strategy.info["name"]).to eq "Sammy the Shark"
      expect(strategy.info["email"]).to eq "sammy@digitalocean.com"
    end

    it "does apply user properties from access token callback in after_authenticate" do
      SiteSetting.oauth2_fetch_user_details = true
      authenticator.stubs(:fetch_user_details).returns(email: "sammy@digitalocean.com")
      result = authenticator.after_authenticate(auth)

      expect(result.extra_data[:uid]).to eq "e028b1b918853eca7fba208a9d7e9d29a6e93c57"
      expect(result.name).to eq "Sammy the Shark"
      expect(result.email).to eq "sammy@digitalocean.com"
    end

    it "does work if user details are not fetched" do
      SiteSetting.oauth2_fetch_user_details = false
      result = authenticator.after_authenticate(auth)

      expect(result.extra_data[:uid]).to eq "e028b1b918853eca7fba208a9d7e9d29a6e93c57"
      expect(result.name).to eq "Sammy the Shark"
      expect(result.email).to eq "sammy@digitalocean.com"
    end
  end

  describe "group synchronization" do
    let(:user) { Fabricate(:user) }
    let(:authenticator) { OAuth2BasicAuthenticator.new }
    let(:group1) { Fabricate(:group, name: "developers", automatic: false) }
    let(:group2) { Fabricate(:group, name: "admins", automatic: false) }
    let(:group3) { Fabricate(:group, name: "managers", automatic: false) }

    let(:auth_with_groups) do
      OmniAuth::AuthHash.new(
        "provider" => "oauth2_basic",
        "credentials" => { token: "token" },
        "uid" => "123456789",
        "info" => { id: "id" },
        "extra" => { "groups" => ["developers", "admins"] }
      )
    end

    before do
      SiteSetting.oauth2_enabled = true
      SiteSetting.oauth2_fetch_user_details = true
      SiteSetting.oauth2_user_json_url = "https://provider.com/user"
      SiteSetting.oauth2_json_groups_path = "groups"
      SiteSetting.oauth2_synchronize_groups = true
    end

    describe "synchronize_groups method" do
      it "creates groups that don't exist" do
        expect { 
          authenticator.synchronize_groups(user, ["newgroup1", "newgroup2"]) 
        }.to change { Group.count }.by(2)
        
        expect(Group.find_by(name: "newgroup1")).to be_present
        expect(Group.find_by(name: "newgroup2")).to be_present
      end

      it "adds user to specified groups" do
        group1 # create the group
        group2 # create the group
        
        expect { 
          authenticator.synchronize_groups(user, ["developers", "admins"]) 
        }.to change { user.groups.count }.by(2)
        
        expect(user.groups).to include(group1, group2)
      end

      it "removes user from groups not in the list" do
        group1 # create the group  
        group2 # create the group
        group3 # create the group
        
        # Add user to all three groups initially
        user.groups << [group1, group2, group3]
        
        # Synchronize with only two groups
        expect { 
          authenticator.synchronize_groups(user, ["developers", "admins"]) 
        }.to change { user.groups.count }.from(3).to(2)
        
        expect(user.groups).to include(group1, group2)
        expect(user.groups).not_to include(group3)
      end

      it "handles mixed case group names" do
        authenticator.synchronize_groups(user, ["Developers", "ADMINS"])
        
        # Should create lowercase groups
        expect(Group.find_by(name: "developers")).to be_present
        expect(Group.find_by(name: "admins")).to be_present
        expect(user.groups.pluck(:name)).to include("developers", "admins")
      end

      it "handles group names with spaces" do
        authenticator.synchronize_groups(user, ["Project Managers", "Team Leads"])
        
        # Should create groups with underscores
        expect(Group.find_by(name: "project_managers")).to be_present
        expect(Group.find_by(name: "team_leads")).to be_present
      end

      it "doesn't affect automatic groups" do
        automatic_group = Fabricate(:group, name: "trust_level_1", automatic: true)
        user.groups << automatic_group
        
        original_count = user.groups.where(automatic: true).count
        authenticator.synchronize_groups(user, ["developers"])
        
        expect(user.groups.where(automatic: true).count).to eq(original_count)
        expect(user.groups).to include(automatic_group)
      end

      it "logs group synchronization activity" do
        SiteSetting.oauth2_debug_auth = true
        
        Rails.logger.expects(:warn).with(regexp_matches(/synchronizing groups for user/))
        Rails.logger.expects(:warn).with(regexp_matches(/processed group names: /))
        Rails.logger.expects(:warn).with(regexp_matches(/creating group/)).at_least_once
        
        authenticator.synchronize_groups(user, ["newgroup"])
      end

      it "handles empty groups list" do
        group1 # create the group
        user.groups << group1
        
        expect { 
          authenticator.synchronize_groups(user, []) 
        }.to change { user.groups.count }.from(1).to(0)
      end

      it "handles nil groups parameter" do
        expect { 
          authenticator.synchronize_groups(user, nil) 
        }.not_to raise_error
      end

      it "handles string input with comma-separated groups" do
        expect { 
          authenticator.synchronize_groups(user, "developers,admins, managers") 
        }.to change { Group.count }.by(3)
        
        expect(Group.find_by(name: "developers")).to be_present
        expect(Group.find_by(name: "admins")).to be_present
        expect(Group.find_by(name: "managers")).to be_present
        expect(user.groups.pluck(:name)).to include("developers", "admins", "managers")
      end

      it "handles empty string input" do
        group1 # create group
        user.groups << group1
        
        expect { 
          authenticator.synchronize_groups(user, "") 
        }.to change { user.groups.count }.from(1).to(0)
      end

      it "handles mixed data types in array" do
        expect { 
          authenticator.synchronize_groups(user, ["developers", :admins, 123]) 
        }.to change { Group.count }.by(3)
        
        expect(Group.find_by(name: "developers")).to be_present
        expect(Group.find_by(name: "admins")).to be_present
        expect(Group.find_by(name: "123")).to be_present
      end

      it "ignores blank group names" do
        expect { 
          authenticator.synchronize_groups(user, ["developers", "", "  ", "admins"]) 
        }.to change { Group.count }.by(2)
        
        expect(Group.find_by(name: "developers")).to be_present
        expect(Group.find_by(name: "admins")).to be_present
        expect(user.groups.count).to eq(2)
      end
    end

    describe "after_authenticate with group sync" do
      before do
        # Mock the HTTP request for user details
        stub_request(:get, SiteSetting.oauth2_user_json_url)
          .to_return(
            status: 200,
            body: '{"email":"test@example.com","groups":["developers","admins"]}'
          )
        SiteSetting.oauth2_json_email_path = "email"
        SiteSetting.oauth2_json_groups_path = "groups"
      end

      it "synchronizes groups for existing users" do
        existing_user = Fabricate(:user, email: "test@example.com")
        group1 # create groups
        group2
        
        result = authenticator.after_authenticate(auth_with_groups)
        
        expect(result.user).to eq(existing_user)
        expect(existing_user.reload.groups).to include(group1, group2)
      end

      it "stores groups in auth extra for new users" do
        auth_with_groups["info"]["email"] = "newuser@example.com"
        
        result = authenticator.after_authenticate(auth_with_groups)
        
        expect(result.extra_data).to be_present
        # The groups should be stored for later processing in after_create_account
      end

      it "doesn't sync groups when setting is disabled" do
        SiteSetting.oauth2_synchronize_groups = false
        existing_user = Fabricate(:user, email: "test@example.com")
        
        result = authenticator.after_authenticate(auth_with_groups)
        
        expect(existing_user.reload.groups.where(automatic: false)).to be_empty
      end

      it "doesn't sync groups when fetch_user_details is disabled" do
        SiteSetting.oauth2_fetch_user_details = false
        existing_user = Fabricate(:user, email: "test@example.com")
        
        result = authenticator.after_authenticate(auth_with_groups)
        
        expect(existing_user.reload.groups.where(automatic: false)).to be_empty
      end
    end

    describe "after_create_account with group sync" do
      let(:new_user) { Fabricate.build(:user, email: "newuser@example.com") }
      let(:auth_result) do
        auth_hash = auth_with_groups.dup
        auth_hash["extra"]["groups"] = ["developers", "managers"]
        auth_hash
      end

      it "synchronizes groups for new users" do
        group1 # create groups
        group3
        
        authenticator.after_create_account(new_user, auth_result)
        
        expect(new_user.groups).to include(group1, group3)
      end

      it "creates groups that don't exist during account creation" do
        expect { 
          authenticator.after_create_account(new_user, auth_result) 
        }.to change { Group.count }.by(2)
        
        expect(Group.find_by(name: "developers")).to be_present
        expect(Group.find_by(name: "managers")).to be_present
      end

      it "doesn't sync groups when setting is disabled" do
        SiteSetting.oauth2_synchronize_groups = false
        
        authenticator.after_create_account(new_user, auth_result)
        
        expect(new_user.groups.where(automatic: false)).to be_empty
      end

      it "handles missing groups data gracefully" do
        auth_without_groups = auth_with_groups.dup
        auth_without_groups["extra"].delete("groups")
        
        expect { 
          authenticator.after_create_account(new_user, auth_without_groups) 
        }.not_to raise_error
      end
    end

    describe "json_walk for groups" do
      it "can extract groups from nested JSON" do
        authenticator = OAuth2BasicAuthenticator.new
        json_string = '{"user":{"roles":["developer","admin","manager"]}}'
        SiteSetting.oauth2_json_groups_path = "user.roles"
        
        result = authenticator.json_walk({}, JSON.parse(json_string), :groups)
        
        expect(result).to eq(["developer", "admin", "manager"])
      end

      it "can extract groups from flat JSON" do
        authenticator = OAuth2BasicAuthenticator.new
        json_string = '{"groups":["team1","team2"]}'
        SiteSetting.oauth2_json_groups_path = "groups"
        
        result = authenticator.json_walk({}, JSON.parse(json_string), :groups)
        
        expect(result).to eq(["team1", "team2"])
      end

      it "handles comma-separated group strings" do
        authenticator = OAuth2BasicAuthenticator.new
        json_string = '{"roles":"developer,admin,manager"}'
        SiteSetting.oauth2_json_groups_path = "roles"
        
        result = authenticator.json_walk({}, JSON.parse(json_string), :groups)
        
        expect(result).to eq("developer,admin,manager")
        
        # Test that synchronize_groups can handle this format
        expect { 
          authenticator.synchronize_groups(user, result.split(",")) 
        }.to change { Group.count }.by(3)
      end
    end

    describe "integration with GroupActionLogger" do
      before { SiteSetting.oauth2_debug_auth = true }

      it "logs group additions" do
        group1 # create group
        
        expect(GroupActionLogger).to receive(:new).with(Discourse.system_user, group1).and_call_original
        expect_any_instance_of(GroupActionLogger).to receive(:log_add_user_to_group).with(user)
        
        authenticator.synchronize_groups(user, ["developers"])
      end

      it "logs group removals" do
        group1 # create group
        user.groups << group1
        
        expect(GroupActionLogger).to receive(:new).with(Discourse.system_user, group1).and_call_original
        expect_any_instance_of(GroupActionLogger).to receive(:log_remove_user_from_group).with(user)
        
        authenticator.synchronize_groups(user, [])
      end
    end
  end
end
