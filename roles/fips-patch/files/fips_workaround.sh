# WARNING: for testing only: don't apply to production without testing.
# A set of workaround patches to use different hash algorithm in Foreman and log the usage instead of failing right away.

# http://projects.theforeman.org/issues/21750
function rails-patch {
  if [ -e /opt/rh/tfm-ror51/root/usr/share/gems/gems/activesupport-*/lib/active_support/digest.rb ]
  then
    echo "Rails already patched"
    return
  fi
  cd /opt/rh/tfm-ror51/root/usr/share/gems/gems/actionpack-*

  cat <<PATCH | patch -p2
diff --git a/actionpack/lib/action_dispatch/http/cache.rb b/actionpack/lib/action_dispatch/http/cache.rb
index 3328ce17a0f9..a8febc32b3af 100644
--- a/actionpack/lib/action_dispatch/http/cache.rb
+++ b/actionpack/lib/action_dispatch/http/cache.rb
@@ -133,7 +133,7 @@ def generate_weak_etag(validators)
         end
 
         def generate_strong_etag(validators)
-          %("#{Digest::MD5.hexdigest(ActiveSupport::Cache.expand_cache_key(validators))}")
+          %("#{ActiveSupport::Digest.hexdigest(ActiveSupport::Cache.expand_cache_key(validators))}")
         end
 
         def cache_control_segments
PATCH

  cd /opt/rh/tfm-ror51/root/usr/share/gems/gems/actionview-*
  cat <<PATCH | patch -p2
diff --git a/actionview/lib/action_view/digestor.rb b/actionview/lib/action_view/digestor.rb
index dfd62bdcfd86..1cf0bd3016f9 100644
--- a/actionview/lib/action_view/digestor.rb
+++ b/actionview/lib/action_view/digestor.rb
@@ -89,7 +89,7 @@ def initialize(name, logical_name, template, children = [])
       end
 
       def digest(finder, stack = [])
-        Digest::MD5.hexdigest("#{template.source}-#{dependency_digest(finder, stack)}")
+        ActiveSupport::Digest.hexdigest("#{template.source}-#{dependency_digest(finder, stack)}")
       end
 
       def dependency_digest(finder, stack)
PATCH

  cd /opt/rh/tfm-ror51/root/usr/share/gems/gems/activerecord-*
  cat <<PATCH | patch -p2
diff --git a/activerecord/lib/active_record/collection_cache_key.rb b/activerecord/lib/active_record/collection_cache_key.rb
index 88b398ad4513..023d144693ee 100644
--- a/activerecord/lib/active_record/collection_cache_key.rb
+++ b/activerecord/lib/active_record/collection_cache_key.rb
@@ -3,7 +3,7 @@
 module ActiveRecord
   module CollectionCacheKey
     def collection_cache_key(collection = all, timestamp_column = :updated_at) # :nodoc:
-      query_signature = Digest::MD5.hexdigest(collection.to_sql)
+      query_signature = ActiveSupport::Digest.hexdigest(collection.to_sql)
       key = "#{collection.model_name.cache_key}/query-#{query_signature}"

       if collection.loaded?
PATCH

  cd /opt/rh/tfm-ror51/root/usr/share/gems/gems/activesupport-*
  cat <<PATCH | patch -p1
diff --git a/lib/active_support.rb b/lib/active_support.rb
index 03e3ce8..4c72d68 100644
--- a/lib/active_support.rb
+++ b/lib/active_support.rb
@@ -50,6 +50,7 @@ module ActiveSupport
     autoload :Callbacks
     autoload :Configurable
     autoload :Deprecation
+    autoload :Digest
     autoload :Gzip
     autoload :Inflector
     autoload :JSON
diff --git a/lib/active_support/cache/file_store.rb b/lib/active_support/cache/file_store.rb
index 945f50a..7c0a81e 100644
--- a/lib/active_support/cache/file_store.rb
+++ b/lib/active_support/cache/file_store.rb
@@ -120,7 +120,7 @@ module ActiveSupport
           fname = URI.encode_www_form_component(key)
 
           if fname.size > FILEPATH_MAX_SIZE
-            fname = Digest::MD5.hexdigest(key)
+            fname = ActiveSupport::Digest.hexdigest(key)
           end
 
           hash = Zlib.adler32(fname)
diff --git a/lib/active_support/cache/mem_cache_store.rb b/lib/active_support/cache/mem_cache_store.rb
index e09cee3..0f9b4c1 100644
--- a/lib/active_support/cache/mem_cache_store.rb
+++ b/lib/active_support/cache/mem_cache_store.rb
@@ -5,7 +5,6 @@ rescue LoadError => e
   raise e
 end
 
-require "digest/md5"
 require "active_support/core_ext/marshal"
 require "active_support/core_ext/array/extract_options"
 
@@ -175,7 +174,7 @@ module ActiveSupport
           key = super.dup
           key = key.force_encoding(Encoding::ASCII_8BIT)
           key = key.gsub(ESCAPE_KEY_CHARS) { |match| "%#{match.getbyte(0).to_s(16).upcase}" }
-          key = "#{key[0, 213]}:md5:#{Digest::MD5.hexdigest(key)}" if key.size > 250
+          key = "#{key[0, 213]}:md5:#{ActiveSupport::Digest.hexdigest(key)}" if key.size > 250
           key
         end
 
diff --git a/lib/active_support/digest.rb b/lib/active_support/digest.rb
new file mode 100644
index 0000000..a030741
--- /dev/null
+++ b/lib/active_support/digest.rb
@@ -0,0 +1,20 @@
+# frozen_string_literal: true
+
+module ActiveSupport
+  class Digest #:nodoc:
+    class <<self
+      def hash_digest_class
+        @hash_digest_class || ::Digest::MD5
+      end
+
+      def hash_digest_class=(klass)
+        raise ArgumentError, "#{klass} is expected to implement hexdigest class method" unless klass.respond_to?(:hexdigest)
+        @hash_digest_class = klass
+      end
+
+      def hexdigest(arg)
+        hash_digest_class.hexdigest(arg)[0...32]
+      end
+    end
+  end
+end
diff --git a/lib/active_support/railtie.rb b/lib/active_support/railtie.rb
index b875875..3401cca 100644
--- a/lib/active_support/railtie.rb
+++ b/lib/active_support/railtie.rb
@@ -47,5 +47,12 @@ module ActiveSupport
         ActiveSupport.send(k, v) if ActiveSupport.respond_to? k
       end
     end
+
+    initializer "active_support.set_hash_digest_class" do |app|
+      if app.config.active_support.respond_to?(:hash_digest_class) && app.config.active_support.hash_digest_class
+        ActiveSupport::Digest.hash_digest_class =
+          app.config.active_support.hash_digest_class
+      end
+    end
   end
 end
PATCH
}

# http://projects.theforeman.org/issues/23128
function deface-patch {
  cd /opt/theforeman/tfm/root/usr/share/gems/gems/deface-*
  if [ -e lib/deface/digest.rb ]
  then
    echo "Deface already patched"
    return
  fi

  cat <<PATCH | patch -p1
diff --git a/lib/deface.rb b/lib/deface.rb
index b952169..e47fdf0 100644
--- a/lib/deface.rb
+++ b/lib/deface.rb
@@ -4,6 +4,7 @@ require "deface/template_helper"
 require "deface/original_validator"
 require "deface/applicator"
 require "deface/search"
+require "deface/digest"
 require "deface/override"
 require "deface/parser"
 require "deface/dsl/loader"
@@ -42,6 +43,10 @@ module Deface
     require "deface/railtie"
   end
 
+  if defined?(ActiveSupport::Digest)
+    Deface::Digest.digest_class = ActiveSupport::Digest
+  end
+
   # Exceptions
   class DefaceError < StandardError; end
 
diff --git a/lib/deface/action_view_extensions.rb b/lib/deface/action_view_extensions.rb
index 049daff..f182a2a 100644
--- a/lib/deface/action_view_extensions.rb
+++ b/lib/deface/action_view_extensions.rb
@@ -52,7 +52,7 @@ ActionView::Template.class_eval do
       deface_hash = Deface::Override.digest(:virtual_path => @virtual_path)
 
       #we digest the whole method name as if it gets too long there's problems
-      "_#{Digest::MD5.new.update("#{deface_hash}_#{method_name_without_deface}").hexdigest}"
+      "_#{Deface::Digest.hexdigest("#{deface_hash}_#{method_name_without_deface}")}"
     end
 
   private
diff --git a/lib/deface/digest.rb b/lib/deface/digest.rb
new file mode 100644
index 0000000..af398ce
--- /dev/null
+++ b/lib/deface/digest.rb
@@ -0,0 +1,17 @@
+module Deface
+  class Digest
+    class <<self
+      def digest_class
+        @digest_class || ::Digest::MD5
+      end
+
+      def digest_class=(klass)
+        @digest_class = klass
+      end
+
+      def hexdigest(arg)
+        @digest_class.hexdigest(arg)[0...32]
+      end
+    end
+  end
+end
diff --git a/lib/deface/original_validator.rb b/lib/deface/original_validator.rb
index 60909d0..8dea389 100644
--- a/lib/deface/original_validator.rb
+++ b/lib/deface/original_validator.rb
@@ -11,7 +11,7 @@ module Deface
     def validate_original(match)
       match = match.map(&:to_s).join if match.is_a? Array
 
-      hashed_original = Digest::SHA1.hexdigest(match.to_s.gsub(/\s/, ''))
+      hashed_original = ::Digest::SHA1.hexdigest(match.to_s.gsub(/\s/, ''))
 
       if @args[:original].present?
         valid = @args[:original] == hashed_original
diff --git a/lib/deface/override.rb b/lib/deface/override.rb
index ecc3bc3..b37893c 100644
--- a/lib/deface/override.rb
+++ b/lib/deface/override.rb
@@ -185,7 +185,8 @@ module Deface
     # used to determine if an override has changed
     #
     def digest
-      Digest::MD5.new.update(@args.keys.map(&:to_s).sort.concat(@args.values.map(&:to_s).sort).join).hexdigest
+      to_hash = @args.keys.map(&:to_s).sort.concat(@args.values.map(&:to_s).sort).join
+      Deface::Digest.hexdigest(to_hash)
     end
 
     # Creates MD5 of all overrides that apply to a particular
@@ -195,8 +196,8 @@ module Deface
     #
     def self.digest(details)
       overrides = self.find(details)
-
-      Digest::MD5.new.update(overrides.inject('') { |digest, override| digest << override.digest }).hexdigest
+      to_hash = overrides.inject('') { |digest, override| digest << override.digest }
+      Deface::Digest.hexdigest(to_hash)
     end
 
     def self.all
PATCH
}

# http://projects.theforeman.org/issues/22583
function apipie-patch {
  cd /opt/theforeman/tfm/root/usr/share/gems/gems/apipie-rails-*
  if ! grep -i md5 lib/apipie/application.rb
  then
    echo "Apipie already patched"
    return
  fi
  cat <<PATCH | patch -p1
diff --git a/lib/apipie/application.rb b/lib/apipie/application.rb
index 3be71062..b0b19cfd 100644
--- a/lib/apipie/application.rb
+++ b/lib/apipie/application.rb
@@ -1,7 +1,7 @@
 require 'apipie/static_dispatcher'
 require 'apipie/routes_formatter'
 require 'yaml'
-require 'digest/md5'
+require 'digest/sha1'
 require 'json'
 
 module Apipie
@@ -341,7 +341,7 @@ def compute_checksum
           all.update(version => Apipie.to_json(version))
         end
       end
-      Digest::MD5.hexdigest(JSON.dump(all_docs))
+      Digest::SHA1.hexdigest(JSON.dump(all_docs))
     end
 
     def checksum
PATCH
}

# http://projects.theforeman.org/issues/23312
function angular-rails-templates-patch {
  if ! [ -e /opt/theforeman/tfm/root/usr/share/gems/gems/angular-rails-templates-* ]
  then
    echo "angular-rails-templates is not present, skipping"
    return
  fi

  cd /opt/theforeman/tfm/root/usr/share/gems/gems/angular-rails-templates-*
  if grep -i 'ActiveSupport::Digest' lib/angular-rails-templates/engine.rb
  then
    echo "angular-rails-templates already patched"
    return
  fi
  cat <<PATCH | patch -p1
diff --git a/lib/angular-rails-templates/engine.rb b/lib/angular-rails-templates/engine.rb
index 3c509a8..20467d0 100644
--- a/lib/angular-rails-templates/engine.rb
+++ b/lib/angular-rails-templates/engine.rb
@@ -37,10 +37,11 @@ class Engine < ::Rails::Engine
 
       # Sprockets Cache Busting
       # If ART's version or settings change, expire and recompile all assets
+      hash_digest = defined?(ActiveSupport::Digest) ? ActiveSupport::Digest : Digest::MD5
       app.config.assets.version = [
         app.config.assets.version,
         'ART',
-        Digest::MD5.hexdigest("#{VERSION}-#{app.config.angular_templates}")
+        hash_digest.hexdigest("#{VERSION}-#{app.config.angular_templates}")
       ].join '-'
     end
PATCH
}

function foreman-workaround {
  if [ -e /usr/share/foreman/config/initializers/0000_fips_workaround.rb ]
  then
    echo "Foreman already patched"
    return
  fi
  cat <<RUBY > /usr/share/foreman/config/initializers/0000_fips_workaround.rb
# To force Rails to use different digest class from https://github.com/rails/rails/commit/659c516bef2781cc66865fc78ed5dce682566d26 
ActiveSupport::Digest.hash_digest_class = ::Digest::SHA1

require 'digest/md5'
require 'digest/sha1'

class Digest::MD5
  class << self
    Digest::MD5.public_methods.each do |method|
      define_method method do |*args, &block|
        Rails.logger.warn("FIPS issue: calling '#{method}' from\n#{caller.join("\n")}")
        Digest::SHA1.send(method, *args, &block)
      end
    end
  end
end
RUBY
}

apipie-patch
rails-patch
deface-patch
angular-rails-templates-patch
foreman-workaround
