using System;
using System.Collections.Generic;
using System.Linq;
using EPiServer.DataAbstraction;
using EPiServer.DataAbstraction.Activities;
using EPiServer.DataAbstraction.Activities.Internal;
using EPiServer.Framework;
using EPiServer.Framework.Initialization;
using EPiServer.Logging;
using EPiServer.Security;
using Swapcode.Episerver.AuditLog.Activities;

namespace Swapcode.Episerver.AuditLog
{
    /// <summary>
    /// Initialization module to initialize the Episerver content security change logging.
    /// </summary>
    [InitializableModule]
    [ModuleDependency(typeof(EPiServer.Web.InitializationModule))]
    public class AuditLogInitializationModule : IInitializableModule
    {
        /// <summary>
        /// Reference to logger.
        /// </summary>
        private static readonly ILogger Logger = LogManager.GetLogger(typeof(AuditLogInitializationModule));

        /// <summary>
        /// Is the module initialized.
        /// </summary>
        private bool _isInitialized;

        /// <summary>
        /// Reference to activity repository.
        /// </summary>
        private IActivityRepository _activityRepository;

        public void Initialize(InitializationEngine context)
        {
            if (_isInitialized)
            {
                return;
            }

            // get service locator
            var locator = context?.Locate?.Advanced;

            // perhaps too much safe guarding but just making sure this module will not blow up totally the start-up
            // if there is no service locator, most likely nothing else works either :D
            if (locator == null)
            {
                Logger.Error("IServiceLocator is null from InitializationEngine. Audit logging not active.");
                return;
            }

            try
            {
                // register the custom ContentSecurityActivity and the action types
                RegisterContentSecurityActivity(locator.GetInstance<IActivityTypeRegistry>());
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to register ContentSecurityActivity and action types. Audit logging not active.", ex);
                return;
            }

            try
            {
                _activityRepository = locator.GetInstance<IActivityRepository>();
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to get the required IActivityRepository service. Audit logging not active.", ex);
                return;
            }

            try
            {
                var repo = locator.GetInstance<IContentSecurityRepository>();
                repo.ContentSecuritySaved += ContentSecuritySaved;
            }
            catch (Exception ex)
            {
                Logger.Error("Failed to register content security saved handler. Audit logging not active.", ex);
                return;
            }

            _isInitialized = true;
        }

        public void Uninitialize(InitializationEngine context)
        {
            if (_isInitialized)
            {
                try
                {
                    var repo = context?.Locate?.Advanced?.GetInstance<IContentSecurityRepository>();

                    if (repo != null)
                    {
                        repo.ContentSecuritySaved -= ContentSecuritySaved;
                        _isInitialized = false;
                    }
                    else
                    {
                        Logger.Warning("Uninitialize called but couldn't get the IContentSecurityRepository service to unregister event handler.");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error("Failed to uninitialize the content security saved handler.", ex);
                }
            }
        }

        /// <summary>
        /// Handles the <see cref="IContentSecurityRepository.ContentSecuritySaved"/> event and logs the changes.
        /// </summary>
        /// <param name="sender">Event sender</param>
        /// <param name="e">ContentSecuritySaved event <see cref="ContentSecurityEventArg"/> where from the log message is created</param>
        private void ContentSecuritySaved(object sender, ContentSecurityEventArg e)
        {
            try
            {
                // what access rights changes were made, target can be user or group (including visitor groups if those are set to be usable to protect content)
                var permissions = e.ContentSecurityDescriptor?.Entries?.Select(entry => $"{entry.EntityType}: {entry.Name} access level set to: {entry.Access}.");

                // this is always null/empty, why? one would assume we would get the creator info here
                //string creator = e.ContentSecurityDescriptor.Creator;

                // this is guranteed to return a valid principal, so use this instead of creator
                string userFromContext = PrincipalInfo.CurrentPrincipal.Identity.Name;

                // create the message of the access rights change
                string msg = $"Access rights changed by '{userFromContext}' to content id {e.ContentLink}, save type: {e.SecuritySaveType}. Following changes were made: {string.Join(" ", permissions)}";

                // log also using the logger implementation
                if (Logger.IsInformationEnabled())
                {
                    Logger.Information(msg);
                }

                // the logged data to activity log
                // we could have multiple keys for example to format the data in the 'change log' view
                // now simply push everything into one key
                Dictionary<string, string> activityData = new Dictionary<string, string>
                {
                    { "Message", msg }
                };

                var activity = new ContentSecurityActivity(e.SecuritySaveType, activityData);

                var result = _activityRepository.SaveAsync(activity).GetAwaiter().GetResult();

                if (Logger.IsDebugEnabled())
                {
                    Logger.Debug($"New activity saved with id: {result}.");
                }
            }
            catch (Exception ex)
            {
                // important to handle exceptions here so that it will not cause issues in the UI even if this fails
                Logger.Error("Failed to handle content security saved event.", ex);
            }
        }

        /// <summary>
        /// Register the <see cref="ContentSecurityActivity"/> with <see cref="SecuritySaveType"/> enum values.
        /// </summary>
        /// <param name="activityTypeRegistry"><see cref="IActivityTypeRegistry"/> instance used for registering the <see cref="ContentSecurityActivity"/> activity.</param>
        private void RegisterContentSecurityActivity(IActivityTypeRegistry activityTypeRegistry)
        {
            if (activityTypeRegistry == null)
            {
                throw new ArgumentNullException(nameof(activityTypeRegistry));
            }

            // this is similiar code that the Episerver implementations use to register the activities
            // NOTE! The enum value None, value zero is excluded from the list as the UI will never show that
            // in the dropdown filter in 'change log' view, assumed to be filter that shows all
            ActivityType activityType = new ActivityType(ContentSecurityActivity.ActivityTypeName,
                from SecuritySaveType x in Enum.GetValues(typeof(SecuritySaveType))
                where x != SecuritySaveType.None
                select new ActionType((int)x, x.ToString()));

            // the implementation calls AddOrUpdate so it is safe to always call it
            // the backing type currently is ConcurrentDictionary not database
            activityTypeRegistry.Register(activityType);
        }
    }
}
