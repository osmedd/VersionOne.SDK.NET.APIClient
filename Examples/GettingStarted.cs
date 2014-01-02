﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;

namespace VersionOne.SDK.APIClient.Examples
{
    public class GettingStarted
    {

        private readonly EnvironmentContext _context;

        public GettingStarted()
        {
            _context = new EnvironmentContext();
        }

        public IV1Configuration GetV1Configuration()
        {
            return _context.V1Configuration;
        }

        public void GetStoryAndDefectTrackingLevel()
        {

            LogResult(string.Concat("Story tracking level:  ", _context.V1Configuration.StoryTrackingLevel));
            LogResult(string.Concat("Defect tracking level:  ", _context.V1Configuration.DefectTrackingLevel));

            /***** OUTPUT EXAMPLE *****
            Story tracking level:  Mix
            Defect tracking level:  On
            ******************/

        }

        public Asset AddNewAsset()
        {
            var projectId = Oid.FromToken("Scope:0", _context.MetaModel);
            var assetType = _context.MetaModel.GetAssetType("Story");
            var newStory = _context.Services.New(assetType, projectId);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            newStory.SetAttributeValue(nameAttribute, "My New Story");
            _context.Services.Save(newStory);

            LogResult(newStory.Oid.Token,
                GetValue(newStory.GetAttribute(assetType.GetAttributeDefinition("Scope")).Value),
                GetValue(newStory.GetAttribute(nameAttribute).Value));

            /***** OUTPUT *****
             Story:1094
             Scope:1012
             My New Story
             ******************/

            return newStory;
        }

        public Asset AddNewAssetWithProxy()
        {
            
            var projectId = Oid.FromToken("Scope:0", _context.MetaModelWithProxy);
            var assetType = _context.MetaModelWithProxy.GetAssetType("Story");
            var newStory = _context.ServicesWithProxy.New(assetType, projectId);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            
            newStory.SetAttributeValue(nameAttribute, "My New Story");
            _context.ServicesWithProxy.Save(newStory);

            LogResult(newStory.Oid.Token,
                GetValue(newStory.GetAttribute(assetType.GetAttributeDefinition("Scope")).Value),
                GetValue(newStory.GetAttribute(nameAttribute).Value));

            /***** OUTPUT *****
             Story:1094
             Scope:1012
             My New Story
             ******************/

            return newStory;

        }

        public bool DeleteAnAsset()
        {

            var story = AddNewAsset();
            var deleteOperation = _context.MetaModel.GetOperation("Story.Delete");
            var deletedId = _context.Services.ExecuteOperation(deleteOperation, story.Oid);
            var query = new Query(deletedId.Momentless);

            try
            {
                QueryResult result = _context.Services.Retrieve(query);
            }
            catch (ConnectionException e)
            {
                LogResult(string.Format("Story has been deleted: {0}.  Exception was:  {1}", story.Oid.Momentless, e.InnerException.Message));
            }

            /***** OUTPUT *****
             Story has been deleted: Story:1049
             ******************/

            return true;

        }

        public Asset CloseAnAsset()
        {

            var story = AddNewAsset();
            var closeOperation = _context.MetaModel.GetOperation("Story.Inactivate");
            var assetName = _context.MetaModel.GetAttributeDefinition("Story.Name");
            var assetState = _context.MetaModel.GetAttributeDefinition("Story.AssetState");
            var closeId = _context.Services.ExecuteOperation(closeOperation, story.Oid);

            var query = new Query(closeId.Momentless);

            query.Selection.Add(assetState);
            query.Selection.Add(assetName);

            var result = _context.Services.Retrieve(query);
            var closedStory = result.Assets[0];
            var state = AssetStateManager.GetAssetStateFromString(GetValue(closedStory.GetAttribute(assetState).Value));

            LogResult(closedStory.Oid.Token,
                closedStory.GetAttribute(assetName).Value.ToString(),
                state.ToString());

            /***** OUTPUT *****
             Story:12079
             My New Story
             Closed
             ******************/

            return closedStory;

        }

        public bool ReOpenAnAsset()
        {

            var story = CloseAnAsset();
            var activateOperation = _context.MetaModel.GetOperation("Story.Reactivate");
            var activeId = _context.Services.ExecuteOperation(activateOperation, story.Oid);

            var query = new Query(activeId.Momentless);
            var assetState = _context.MetaModel.GetAttributeDefinition("Story.AssetState");
            query.Selection.Add(assetState);
            var result = _context.Services.Retrieve(query);
            var activeStory = result.Assets[0];
            var state = AssetStateManager.GetAssetStateFromString(GetValue(activeStory.GetAttribute(assetState)));

            LogResult(activeStory.Oid.ToString(), state.ToString());

            /***** OUTPUT EXAMPLE *****
             Story:1098
             Future
             ******************/

            return true;

        }


        public Asset GetSingleAsset()
        {

            var memberId = Oid.FromToken("Member:20", _context.MetaModel);
            var query = new Query(memberId);
            var nameAttribute = _context.MetaModel.GetAttributeDefinition("Member.Name");
            var emailAttribute = _context.MetaModel.GetAttributeDefinition("Member.Email");

            query.Selection.Add(nameAttribute);
            query.Selection.Add(emailAttribute);

            var result = _context.Services.Retrieve(query);
            var member = result.Assets[0];

            LogResult(member.Oid.Token,
                GetValue(member.GetAttribute(nameAttribute).Value),
                GetValue(member.GetAttribute(emailAttribute).Value));

            /***** OUTPUT EXAMPLE *****
             Member:20
             Administrator
             admin@company.com
             ******************/

            return member;

        }

        public bool EffortTrackingIsEnabled()
        {

            LogResult(_context.V1Configuration.EffortTracking.ToString());

            return _context.V1Configuration.EffortTracking;

            /***** OUTPUT EXAMPLE *****
            False
            ******************/
        }

        public List<Asset> GetMultipleAssets()
        {
            var assetType = _context.MetaModel.GetAssetType("Story");
            var query = new Query(assetType);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            var estimateAttribute = assetType.GetAttributeDefinition("Estimate");

            query.Selection.Add(nameAttribute);
            query.Selection.Add(estimateAttribute);

            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(story =>
                    LogResult(story.Oid.Token,
                        GetValue(story.GetAttribute(nameAttribute).Value),
                        GetValue(story.GetAttribute(estimateAttribute).Value).ToString(CultureInfo.InvariantCulture)));  //stories may not have an estimate assigned.

            /***** OUTPUT EXAMPLE *****
             Story:1083
             View Daily Call Count
             5

             Story:1554
             Multi-View Customer Calendar
             1 ...
             ******************/

            return result.Assets;
        }

        public List<Asset> FindListOfAssets()
        {
            var assetType = _context.MetaModel.GetAssetType("Story");
            var query = new Query(assetType);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            query.Selection.Add(nameAttribute);
            query.Find = new QueryFind("High");  //retrieve only stories marked as high priority
            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(asset => LogResult(GetValue(asset.Oid.Token), GetValue(asset.GetAttribute(nameAttribute).Value)));

            return result.Assets;

        }

        public List<Asset> FilterListOfAssets()
        {
            var assetType = _context.MetaModel.GetAssetType("Task");
            var query = new Query(assetType);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            var todoAttribute = assetType.GetAttributeDefinition("ToDo");

            query.Selection.Add(nameAttribute);
            query.Selection.Add(todoAttribute);

            var toDoTerm = new FilterTerm(todoAttribute);
            toDoTerm.Equal(0);
            query.Filter = toDoTerm;
            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(taskAsset =>
                LogResult(taskAsset.Oid.Token,
                    GetValue(taskAsset.GetAttribute(nameAttribute).Value),
                    GetValue(taskAsset.GetAttribute(todoAttribute).Value.ToString())));

            /***** OUTPUT EXAMPLE *****
             Task:1153
             Code Review
             0

             Task:1154
             Design Component
             0 ...
             ******************/

            return result.Assets;

        }

        public List<Asset> SortListOfAssets()
        {
            var assetType = _context.MetaModel.GetAssetType("Story");
            var query = new Query(assetType);
            var nameAttribute = assetType.GetAttributeDefinition("Name");
            var estimateAttribute = assetType.GetAttributeDefinition("Estimate");

            query.Selection.Add(nameAttribute);
            query.Selection.Add(estimateAttribute);
            query.OrderBy.MinorSort(estimateAttribute, OrderBy.Order.Ascending);

            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(asset =>
                LogResult(asset.Oid.Token,
                    GetValue(asset.GetAttribute(nameAttribute).Value),
                    GetValue(asset.GetAttribute(estimateAttribute).Value)));

            /***** OUTPUT EXAMPLE *****
             Task:1153
             Code Review
             0

             Task:1154
             Design Component
             0 ...
             ******************/

            return result.Assets;

        }

        public List<Asset> PageListOfAssets()
        {

            var storyType = _context.MetaModel.GetAssetType("Story");
            var query = new Query(storyType);
            var nameAttribute = storyType.GetAttributeDefinition("Name");
            var estimateAttribute = storyType.GetAttributeDefinition("Estimate");
            query.Selection.Add(nameAttribute);
            query.Selection.Add(estimateAttribute);
            query.Paging.PageSize = 3;
            query.Paging.Start = 0;
            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(asset =>
                LogResult(asset.Oid.Token,
                    GetValue(asset.GetAttribute(nameAttribute).Value),
                    GetValue(asset.GetAttribute(estimateAttribute).Value)));

            /***** OUTPUT EXAMPLE *****
             Story:1063
             Logon
             2

             Story:1064
             Add Customer Details
             2

             Story:1065
             Add Customer Header
             3
             ******************/

            return result.Assets;
        }

        public List<Asset> HistorySingleAsset()
        {
            var memberType = _context.MetaModel.GetAssetType("Member");
            var query = new Query(memberType, true);
            var idAttribute = memberType.GetAttributeDefinition("ID");
            var changeDateAttribute = memberType.GetAttributeDefinition("ChangeDate");
            var emailAttribute = memberType.GetAttributeDefinition("Email");
            query.Selection.Add(changeDateAttribute);
            query.Selection.Add(emailAttribute);
            var idTerm = new FilterTerm(idAttribute);
            idTerm.Equal("Member:20");
            query.Filter = idTerm;
            var result = _context.Services.Retrieve(query);

            result.Assets.ForEach(asset =>
                LogResult(asset.Oid.Token,
                    GetValue(asset.GetAttribute(changeDateAttribute).Value),
                    GetValue(asset.GetAttribute(emailAttribute).Value)));

            /***** OUTPUT EXAMPLE *****
             Member:1000:105
             4/2/2007 1:22:03 PM
             andre.agile@company.com

             Member:1000:101
             3/29/2007 4:10:29 PM
             andre@company.net
             ******************/

            return result.Assets;

        }

        public List<Asset> HistoryListOfAssets()
        {
            var memberType = _context.MetaModel.GetAssetType("Member");
            var query = new Query(memberType, true);
            var changeDateAttribute = memberType.GetAttributeDefinition("ChangeDate");
            var emailAttribute = memberType.GetAttributeDefinition("Email");
            query.Selection.Add(changeDateAttribute);
            query.Selection.Add(emailAttribute);
            var result = _context.Services.Retrieve(query);
            var memberHistory = result.Assets;

            memberHistory.ForEach(member =>
                LogResult(member.Oid.Token,
                    GetValue(member.GetAttribute(changeDateAttribute).Value),
                    GetValue(member.GetAttribute(emailAttribute))));

            /***** OUTPUT EXAMPLE *****
             Member:20:0
             Thu Nov 30 19:00:00 EST 1899
             null

             Member:20:17183
             Fri Nov 09 09:46:25 EST 2012
             versionone@mailinator.com

             Member:20:17190
             Sun Nov 11 22:59:23 EST 2012
             versionone@mailinator.com

             Member:20:17191
             Sun Nov 11 22:59:47 EST 2012
             versionone@mailinator.com
             ******************/

            return memberHistory;
        }

        public List<Asset> HistoryAsOfTime()
        {
            var storyType = _context.MetaModel.GetAssetType("Story");
            var query = new Query(storyType, true);
            var nameAttribute = storyType.GetAttributeDefinition("Name");
            var estimateAttribute = storyType.GetAttributeDefinition("Estimate");
            query.Selection.Add(nameAttribute);
            query.Selection.Add(estimateAttribute);

            query.AsOf = DateTime.Now.AddDays(-7);
            QueryResult result = _context.Services.Retrieve(query);

            result.Assets.ForEach(asset =>
                LogResult(asset.Oid.Token,
                    GetValue(asset.GetAttribute(nameAttribute).Value),
                    GetValue(asset.GetAttribute(estimateAttribute).Value)));

            /***** OUTPUT EXAMPLE *****
            Story:5807:7830
            Investigate and fix priority update and data integrity issues.
            12
            Story:8440:13019
            OneHundredThousandAndOne1/7/2012 10:24:56 AM_i5

            Story:8564:13143
            OneHundredThousandAndOne1/7/2012 10:26:35 AM_i115

            Story:10194:14838
            Story Object Model Single Call Test 2/13/2012 3:12:18 PM

            Story:8424:13003
            OneHundredThousandAndOne1/7/2012 10:23:39 AM_i3

            Story:9228:13807
            OneHundredThousandAndOne1/7/2012 10:39:17 AM_i466

             ******************/

            return result.Assets;

        }

        public bool UpdateScalarAttribute()
        {
            var storyId = Oid.FromToken("Story:1094", _context.MetaModel);
            var query = new Query(storyId);
            var storyType = _context.MetaModel.GetAssetType("Story");
            var nameAttribute = storyType.GetAttributeDefinition("Name");

            query.Selection.Add(nameAttribute);
            var result = _context.Services.Retrieve(query);
            var story = result.Assets[0];
            var oldName = GetValue(story.GetAttribute(nameAttribute).Value);
            story.SetAttributeValue(nameAttribute, Guid.NewGuid().ToString());
            _context.Services.Save(story);

            LogResult(story.Oid.Token, oldName, GetValue(story.GetAttribute(nameAttribute).Value));

            /***** OUTPUT EXAMPLE *****
             Story:1094:1446
             Logon
             F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4
             ******************/

            return true;
        }

        public bool UpdateSingleValueRelation()
        {

            var storyId = Oid.FromToken("Story:1094", _context.MetaModel);
            var query = new Query(storyId);
            var storyType = _context.MetaModel.GetAssetType("Story");
            var sourceAttribute = storyType.GetAttributeDefinition("Source");
            query.Selection.Add(sourceAttribute);
            var result = _context.Services.Retrieve(query);
            var story = result.Assets[0];
            var oldSource = GetValue(story.GetAttribute(sourceAttribute).Value);
            story.SetAttributeValue(sourceAttribute, GetNextSourceId(oldSource));
            _context.Services.Save(story);

            LogResult(story.Oid.Token, oldSource, GetValue(story.GetAttribute(sourceAttribute).Value));

            /***** OUTPUT EXAMPLE *****
            Story:1094:17726
            StorySource:148
            StorySource:149
            ******************/

            return true;

        }

        public bool UpdateMultiValueRelation()
        {

            var storyId = Oid.FromToken("Story:1124", _context.MetaModel);
            var query = new Query(storyId);
            var storyType = _context.MetaModel.GetAssetType("Story");
            var ownersAttribute = storyType.GetAttributeDefinition("Owners");

            query.Selection.Add(ownersAttribute);

            var result = _context.Services.Retrieve(query);
            var story = result.Assets[0];
            var values = story.GetAttribute(ownersAttribute).Values;
            var owners = values.Cast<object>().ToList();

            if (owners.Count >= 1) story.RemoveAttributeValue(ownersAttribute, owners[0]);

            _context.Services.Save(story);

            return true;

        }

        private static string GetNextSourceId(string oldSource)
        {
            if (oldSource == "StorySource:148") return "StorySource:149";
            if (oldSource == "StorySource:149") return "StorySource:150";
            return "StorySource:148";
        }

        private static string GetValue(object value)
        {
            return value == null ? "No Value Available" : value.ToString();
        }

        private static void LogResult(params string[] results)
        {
            foreach (var result in results)
            {
                Debug.WriteLine(result);
            }
        }

    }
}
